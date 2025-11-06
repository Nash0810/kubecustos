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
	Pid     uint32
	Ppid    uint32
	Comm    [16]byte
	ArgsBuf [512]byte
}

type EnrichedEvent struct {
	PID         uint32
	Comm        string
	FullCommand string
	Pod         *v1.Pod
	NodeName    string
}

// --- Pod Cache Implementation ---

// PodCache holds the mapping from containerID -> Pod
// and caches PID -> Pod lookups
type PodCache struct {
	client *kubernetes.Clientset
	nodeName string

	// Main cache: containerID -> Pod
	containerCache map[string]*v1.Pod
	cacheLock      sync.RWMutex

	// Short-term cache: pid -> containerID
	// This avoids reading /proc/pid/cgroup for every event from the same PID
	pidCache    map[uint32]string
	pidLock     sync.RWMutex
}

// newPodCache creates a new pod cache
func newPodCache(client *kubernetes.Clientset, nodeName string) *PodCache {
	return &PodCache{
		client:         client,
		nodeName:       nodeName,
		containerCache: make(map[string]*v1.Pod),
		pidCache:       make(map[uint32]string),
	}
}

// run starts the cache refresh loop
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

// refresh lists all pods on the node and updates the internal cache
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
			// containerID looks like "containerd://<id>" or "docker://<id>"
			// We just need the <id> part
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
	
	// Clear the PID-to-ContainerID cache as PIDs get reused
	pc.pidLock.Lock()
	pc.pidCache = make(map[uint32]string)
	pc.pidLock.Unlock()

	log.Printf("Pod cache refreshed, %d pods found on node %s", len(pods.Items), pc.nodeName)
	return nil
}

// cgroupRegex matches the container ID from a /proc/pid/cgroup line
// It handles both docker (e.g., /kubepods/pod.../docker-<id>.scope)
// and containerd (e.g., /kubepods/pod.../<id>)
var cgroupRegex = regexp.MustCompile(`.*/(docker|crio|containerd)-?([a-f0-9]{64})\.?`)

// getContainerIDFromPID reads the cgroup file for a PID and extracts the container ID
func (pc *PodCache) getContainerIDFromPID(pid uint32) (string, bool) {
	// 1. Check our fast PID cache
	pc.pidLock.RLock()
	cid, found := pc.pidCache[pid]
	pc.pidLock.RUnlock()
	if found {
		return cid, cid != "" // Return (id, true) if found, or ("", true) if known-host
	}

	// 2. Not in cache, read from /host/proc
	cgroupPath := fmt.Sprintf("/host/proc/%d/cgroup", pid)
	content, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		// Process might have exited
		return "", false
	}

	// 3. Parse the file
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		matches := cgroupRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			containerID := matches[2] // The 64-char hex string
			
			// Store in cache
			pc.pidLock.Lock()
			pc.pidCache[pid] = containerID
			pc.pidLock.Unlock()

			return containerID, true
		}
	}

	// 4. If no match, it's likely a host process
	pc.pidLock.Lock()
	pc.pidCache[pid] = "" // Cache as empty to avoid re-reading
	pc.pidLock.Unlock()
	return "", true // (empty string, but lookup was successful)
}

// --- THIS IS THE UPDATED FUNCTION ---
// FindPodForPID is the main lookup function.
// It now checks the parent's (ppid) cgroup as a fallback.
func (pc *PodCache) FindPodForPID(pid, ppid uint32) *v1.Pod {
	// Try to get container ID from the process PID first
	containerID, found := pc.getContainerIDFromPID(pid)
	if !found {
		// Error reading cgroup, process likely gone
		return nil
	}

	// If the child (pid) is not in a container cgroup (e.g., it's "host"),
	// try to check the parent (ppid). This handles the exec race condition.
	if containerID == "" && ppid > 1 {
		containerID, found = pc.getContainerIDFromPID(ppid)
		if !found {
			return nil
		}
	}

	// If we still have no container ID, it's a host process.
	if containerID == "" {
		return nil
	}

	// Now, look up the container ID in our K8s pod cache
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

// --- Slack & Rules (Unchanged) ---

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
				{Type: "mrkdwn", Text: fmt.Sprintf("*Process Name:*\n`%s`", event.Comm)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*PID:*\n`%d`", event.PID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n`%s`", time.Now().UTC().Format(time.RFC1123))},
			}},
			{Type: "section", Text: &SlackField{Type: "mrkdwn", Text: fmt.Sprintf("*Full Command:*\n```%s```", event.FullCommand)}},
		},
	}
	payload, _ := json.Marshal(msg)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
}

func checkRules(event EnrichedEvent) string {
	if event.Comm == "xmrig" { return "Potential Crypto Miner" }
	if strings.Contains(event.FullCommand, "curl | bash") || strings.Contains(event.FullCommand, "wget | sh") { return "Suspicious Command Pipe" }
	if strings.HasPrefix(event.FullCommand, "/tmp/") { return "Execution from /tmp" }
	return ""
}

// --- Main Function (Refactored) ---

func main() {
	log.Println("Starting KubeCustos Collector...")
	
	// Use a context to manage goroutine shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config, _ := rest.InClusterConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable not set")
	}

	// Start the Pod Cache
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
	defer rd.Close()

	// Goroutine to close ringbuf reader on signal
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
				return // Exit loop
			}
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		// --- THIS IS THE UPDATED CALL SITE ---
		// We now pass both PID and PPID to the lookup function
		sourcePod := podCache.FindPodForPID(event.Pid, event.Ppid)
		// --- END FIX ---

		comm := unix.ByteSliceToString(event.Comm[:])
		end := bytes.IndexByte(event.ArgsBuf[:], 0)
		if end == -1 { end = len(event.ArgsBuf) }
		fullCommand := string(event.ArgsBuf[:end])

		enrichedEvent := EnrichedEvent{
			PID: event.Pid, Comm: comm, FullCommand: fullCommand, Pod: sourcePod, NodeName: nodeName,
		}

		if alertMsg := checkRules(enrichedEvent); alertMsg != "" {
			log.Printf("🚨 ALERT 🚨: %s triggered\n", alertMsg)
			go sendSlackAlert(alertMsg, enrichedEvent)
		}
	}
}