// cmd/collector/main.go
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:embed probe.o
var bpfObject []byte

// bpfEvent must exactly match the C struct
type bpfEvent struct {
	Pid       uint32
	Ppid      uint32
	Comm      [16]byte
	ArgsBuf   [4096]byte // ARGS_BUF_SIZE
	ArgsCount int32
}

type EnrichedEvent struct {
	PID         uint32
	Comm        string
	FullCommand string
	Pod         *v1.Pod
	NodeName    string
}

// MAX_ARG_SIZE Must match the C code
const MAX_ARG_SIZE = 256 

// --- Pod Cache Implementation ---

type PodCache struct {
	client *kubernetes.Clientset
	nodeName string
	containerCache map[string]*v1.Pod
	cacheLock      sync.RWMutex
	pidCache    map[uint32]string
	pidLock     sync.RWMutex
}

func newPodCache(client *kubernetes.Clientset, nodeName string) *PodCache {
	return &PodCache{
		client:         client,
		nodeName:       nodeName,
		containerCache: make(map[string]*v1.Pod),
		pidCache:       make(map[uint32]string),
	}
}

func (pc *PodCache) run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Println("Starting Pod cache...")
	for {
		if err := pc.refresh(); err != nil {
			log.Printf("Error refreshing pod cache: %v", err)
		}

		select {
		case <-ctx.Done():
			log.Println("Stopping Pod cache.")
			return
		case <-ticker.C:
		}
	}
}

func (pc *PodCache) refresh() error {
	pods, err := pc.client.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + pc.nodeName,
	})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	newCache := make(map[string]*v1.Pod)
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, status := range pod.Status.ContainerStatuses {
			parts := strings.Split(status.ContainerID, "://")
			if len(parts) == 2 {
				containerID := parts[1]
				newCache[containerID] = pod
			}
		}
	}

	pc.cacheLock.Lock()
	pc.containerCache = newCache
	pc.cacheLock.Unlock()
	
	pc.pidLock.Lock()
	pc.pidCache = make(map[uint32]string)
	pc.pidLock.Unlock()

	log.Printf("Pod cache refreshed, %d pods found on node %s", len(pods.Items), pc.nodeName)
	return nil
}

// --- THIS IS THE FIX ---
// This regex specifically finds the container ID from cgroupv1 paths
// used by containerd, crio, and docker, based on your log output.
var cgroupRegex = regexp.MustCompile(`(docker|containerd|crio)-([a-f0-9]{64})\.scope`)
// --- END FIX ---

func (pc *PodCache) getContainerIDFromPID(pid uint32) (string, bool) {
	pc.pidLock.RLock()
	cid, found := pc.pidCache[pid]
	pc.pidLock.RUnlock()
	if found {
		return cid, cid != "" 
	}

	cgroupPath := fmt.Sprintf("/host/proc/%d/cgroup", pid)
	content, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		return "", false
	}

	// --- THIS IS THE FIX ---
	// We parse the lines to find the cgroupv1-style ID
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		matches := cgroupRegex.FindStringSubmatch(line)
		// matches[0] = "crio-1ea8da...scope"
		// matches[1] = "crio"
		// matches[2] = "1ea8da..."
		if len(matches) == 3 {
			containerID := matches[2] // The 64-char hex string
			pc.pidLock.Lock()
			pc.pidCache[pid] = containerID
			pc.pidLock.Unlock()
			return containerID, true
		}
	}
	// --- END FIX ---
	
	// If no match, it's a host process
	pc.pidLock.Lock()
	pc.pidCache[pid] = "" 
	pc.pidLock.Unlock()
	return "", true 
}

func (pc *PodCache) FindPodForPID(pid, ppid uint32) *v1.Pod {
	containerID, found := pc.getContainerIDFromPID(pid)
	if !found {
		return nil
	}

	if containerID == "" && ppid > 1 {
		containerID, found = pc.getContainerIDFromPID(ppid)
		if !found {
			return nil
		}
	}

	if containerID == "" {
		return nil
	}

	pc.cacheLock.RLock()
	pod, ok := pc.containerCache[containerID]
	pc.cacheLock.RUnlock()
	if !ok {
		// Cache might be stale, but we don't want to block
		return nil
	}
	return pod
}

// --- End Pod Cache ---

// --- Slack & Rules (Corrected) ---

type SlackField struct { Type string `json:"type"`; Text string `json:"text"` }
type SlackBlock struct { Type string `json:"type"`; Fields []SlackField `json:"fields,omitempty"`; Text *SlackField `json:"text,omitempty"` }
type SlackPayload struct { Blocks []SlackBlock `json:"blocks"` }

func sendSlackAlert(alertMsg string, event EnrichedEvent) {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" { return }
	podName, namespace := "host", "host"
	if event.Pod != nil {
		podName, namespace = event.Pod.Name, event.Pod.Namespace
	}
	msg := SlackPayload{
		Blocks: []SlackBlock{
			{Type: "header", Text: &SlackField{Type: "plain_text", Text: fmt.Sprintf("🚨 KubeCustos Alert: %s", alertMsg)}},
			{Type: "section", Fields: []SlackField{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:*\n`%s/%s`", namespace, podName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Node:*\n`%s`", event.NodeName)},
				{Type: "mrkdwn",Text: fmt.Sprintf("*Process Name:*\n`%s`", event.Comm)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*PID:*\n`%d`", event.PID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n`%s`", time.Now().UTC().Format(time.RFC1123))},
			}},
			{Type: "section", Text: &SlackField{Type: "mrkdwn", Text: fmt.Sprintf("*Full Command:*\n```%s```", event.FullCommand)}},
		},
	}
	payload, _ := json.Marshal(msg)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
}

// --- THIS IS THE FIX ---
// The rules are now more robust and check the FullCommand.
func checkRules(event EnrichedEvent) string {
    // Check Comm (kernel process name, 16-char limit)
	if event.Comm == "xmrig" { return "Potential Crypto Miner" }
    
    // Check FullCommand (the complete command line)
	if strings.Contains(event.FullCommand, "xmrig") { return "Potential Crypto Miner" }
	if strings.Contains(event.FullCommand, "curl | bash") || strings.Contains(event.FullCommand, "wget | sh") { return "Suspicious Command Pipe" }
	if strings.HasPrefix(event.FullCommand, "/tmp/") { return "Execution from /tmp" }
	return ""
}
// --- END FIX ---

// --- Main Function (Parser Updated) ---

func main() {
	log.Println("Starting KubeCustos Collector...")
	
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config, _ := rest.InClusterConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable not set")
	}

	podCache := newPodCache(clientset, nodeName)
	go podCache.run(ctx)

	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil { log.Fatalf("Failed to load eBPF spec: %v", err) }

	var objs struct {
		HandleExecve *ebpf.Program `ebpf:"handle_execve"`
		Events       *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil { log.Fatalf("Failed to load eBPF objects: %v", err) }
	defer objs.HandleExecve.Close(); defer objs.Events.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil { log.Fatalf("attaching tracepoint: %v", err) }
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil { log.Fatalf("opening ringbuf reader: %v", err) }

	go func() {
		<-ctx.Done()
		log.Println("Received signal, closing ringbuf reader...")
		rd.Close()
	}()

	log.Println("Probe attached. Waiting for events...")
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ringbuf closed, exiting event loop.")
				return 
			}
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		sourcePod := podCache.FindPodForPID(event.Pid, event.Ppid)
		comm := unix.ByteSliceToString(event.Comm[:])

        // --- NEW PARSING LOGIC ---
        // We now read from fixed-size slots
        var args []string
        for i := 0; i < int(event.ArgsCount); i++ {
            offset := i * MAX_ARG_SIZE
            if offset >= len(event.ArgsBuf) {
                break
            }

            // Find the null terminator in this slot
            argSlot := event.ArgsBuf[offset:]
            end := bytes.IndexByte(argSlot, 0)
            
            // If no null term, just take the whole slot (or what's left)
            if end == -1 {
				if offset+MAX_ARG_SIZE > len(event.ArgsBuf) {
					end = len(event.ArgsBuf) - offset
				} else {
					end = MAX_ARG_SIZE
				}
            }
			
			// If we have a valid string, add it
            if end > 0 {
                args = append(args, string(argSlot[:end]))
            }
        }
        fullCommand := strings.Join(args, " ")
        // --- END NEW LOGIC ---

		enrichedEvent := EnrichedEvent{
			PID: event.Pid, Comm: comm, FullCommand: fullCommand, Pod: sourcePod, NodeName: nodeName,
		}

		if alertMsg := checkRules(enrichedEvent); alertMsg != "" {
			log.Printf("🚨 ALERT 🚨: %s triggered\n", alertMsg)
			go sendSlackAlert(alertMsg, enrichedEvent)
		}
	}
}