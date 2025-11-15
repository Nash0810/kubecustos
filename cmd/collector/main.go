package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

	// Local informer-based cache
	"github.com/nash-d/kubecustos/pkg/k8s"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:embed probe.o
var bpfObject []byte

// bpfEvent must exactly match the C struct emitted by the eBPF program.
type bpfEvent struct {
	Pid       uint32
	Ppid      uint32
	Comm      [16]byte
	ArgsBuf   [4096]byte
	ArgsCount int32
}

type EnrichedEvent struct {
	PID         uint32
	Comm        string
	FullCommand string
	Pod         *v1.Pod
	NodeName    string
}

const MAX_ARG_SIZE = 256

// --- PID -> containerID cache (local, avoids re-reading /proc repeatedly) ---
var (
	pidCache   = make(map[uint32]string)
	pidCacheMu sync.RWMutex
)

// Some tolerant regexes for multiple runtimes:
// - CRI-O (crio-<64>.scope)
// - containerd / cri-containerd / cri-o .scope variants
// - docker systemd .scope
// Additionally we'll scan for any 64-hex substring if runtime keywords exist in the line.
var (
	// match explicit <runtime>-<64hex>.scope e.g. crio-<id>.scope or cri-containerd-<id>.scope
	scopeRuntimeRe = regexp.MustCompile(`(?i)(crio|cri-containerd|containerd|docker)-([a-f0-9]{64})\.scope`)
	// match docker/containerd style path segments that include a 64 hex id
	genericHex64Re = regexp.MustCompile(`([a-f0-9]{64})`)
	// runtime keywords to reduce false positives
	runtimeKeywords = []string{"crio", "containerd", "cri-containerd", "docker", "kubepods", "docker-"}

	// quick cgroup v2 pattern: look for "kubepods.slice/.../docker-<id>.scope" or similar.
	cgroupIDRe = regexp.MustCompile(`(?:docker|containerd|crio|cri-containerd)[\-/]([a-f0-9]{64})`)
)

// getContainerIDFromPID reads /host/proc/<pid>/cgroup and extracts a container id when possible.
// Returns (containerID, true) when file was read and extract succeeded or was definitely host (empty id with true).
// Returns ("", false) when file could not be read (process likely exited).
func getContainerIDFromPID(pid uint32) (string, bool) {
	// fast local cache
	pidCacheMu.RLock()
	if v, ok := pidCache[pid]; ok {
		pidCacheMu.RUnlock()
		// found in cache; second return indicates "we read it before" (true)
		// but if v=="" it means host process previously determined
		return v, true
	}
	pidCacheMu.RUnlock()

	path := fmt.Sprintf("/host/proc/%d/cgroup", pid)
	b, err := os.ReadFile(path)
	if err != nil {
		// cannot read for this pid (likely exited) -> treat as transient; caller will ignore event
		return "", false
	}
	content := string(b)

	// Try explicit scope runtime pattern
	if m := scopeRuntimeRe.FindStringSubmatch(content); len(m) == 3 {
		id := m[2]
		pidCacheMu.Lock()
		pidCache[pid] = id
		pidCacheMu.Unlock()
		return id, true
	}

	// Try cgroupIDRe (combined)
	if m := cgroupIDRe.FindStringSubmatch(content); len(m) == 2 {
		id := m[1]
		pidCacheMu.Lock()
		pidCache[pid] = id
		pidCacheMu.Unlock()
		return id, true
	}

	// Generic scan for 64-hex but only accept if runtime keywords appear in the same content
	hasKeyword := false
	for _, kw := range runtimeKeywords {
		if strings.Contains(content, kw) {
			hasKeyword = true
			break
		}
	}
	if hasKeyword {
		if gm := genericHex64Re.FindStringSubmatch(content); len(gm) == 2 {
			id := gm[1]
			pidCacheMu.Lock()
			pidCache[pid] = id
			pidCacheMu.Unlock()
			return id, true
		}
	}

	// No runtime container id found -> host process
	pidCacheMu.Lock()
	pidCache[pid] = "" // cache host result so we don't re-read repeatedly
	pidCacheMu.Unlock()
	return "", true
}

// FindPodForPID tries to resolve PID -> containerID -> Pod (via podCache).
// Returns nil when host or unknown.
func FindPodForPID(podCache *k8s.PodCache, pid, ppid uint32) *v1.Pod {
	containerID, ok := getContainerIDFromPID(pid)
	if !ok {
		// transient read error: treat as "don't know"
		return nil
	}

	// if not in a container, try parent (ppid)
	if containerID == "" && ppid > 1 {
		containerID, ok = getContainerIDFromPID(ppid)
		if !ok {
			return nil
		}
	}

	if containerID == "" {
		// host
		return nil
	}

	// PodCache handles informer store scan and API fallback as needed
	return podCache.FindPodByContainerID(containerID)
}

// --- Slack / Alert helpers (unchanged, minor cleanup) ---

type SlackField struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type SlackBlock struct {
	Type   string       `json:"type"`
	Fields []SlackField `json:"fields,omitempty"`
	Text   *SlackField  `json:"text,omitempty"`
}

type SlackPayload struct {
	Blocks []SlackBlock `json:"blocks"`
}

func sendSlackAlert(alertMsg string, event EnrichedEvent) {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}

	podName, namespace := "host", "host"
	if event.Pod != nil {
		podName = event.Pod.Name
		namespace = event.Pod.Namespace
	}

	msg := SlackPayload{
		Blocks: []SlackBlock{
			{
				Type: "header",
				Text: &SlackField{
					Type: "plain_text",
					Text: fmt.Sprintf("🚨 KubeCustos Alert: %s", alertMsg),
				},
			},
			{
				Type: "section",
				Fields: []SlackField{
					{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:*\n`%s/%s`", namespace, podName)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Node:*\n`%s`", event.NodeName)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Process Name:*\n`%s`", event.Comm)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*PID:*\n`%d`", event.PID)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n`%s`", time.Now().UTC().Format(time.RFC1123))},
				},
			},
			{
				Type: "section",
				Text: &SlackField{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*Full Command:*\n```%s```", event.FullCommand),
				},
			},
		},
	}

	payload, _ := json.Marshal(msg)
	_, _ = http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
}

// --- Detection rules ---
func checkRules(event EnrichedEvent) string {
	// ignore noisy runtime daemons that run on host
	if event.Comm == "iptables" || strings.HasPrefix(event.Comm, "runc") ||
		event.Comm == "conmon" || strings.HasPrefix(event.Comm, "containerd-shim") ||
		strings.HasPrefix(event.Comm, "containerd") || event.Comm == "dockerd" {
		return ""
	}

	// crypto miner
	if strings.Contains(event.FullCommand, "xmrig") || event.Comm == "xmrig" {
		return "Potential Crypto Miner"
	}

	// supply-chain patterns (simple)
	if strings.Contains(event.FullCommand, "curl") && strings.Contains(event.FullCommand, "bash") {
		return "Suspicious Command Pipe"
	}
	if strings.Contains(event.FullCommand, "wget") && strings.Contains(event.FullCommand, "sh") {
		return "Suspicious Command Pipe"
	}

	// execution from /tmp
	if strings.HasPrefix(event.FullCommand, "/tmp/") {
		return "Execution from /tmp"
	}

	return ""
}

// --- main ---
func main() {
	log.Println("Starting KubeCustos Collector...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// in-cluster client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("failed to create k8s clientset: %v", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME not set")
	}

	// start pod cache
	log.Println("Starting Pod cache informer...")
	podCache := k8s.NewPodCache(clientset, nodeName)
	if !podCache.Run(ctx) {
		log.Fatal("failed to sync pod cache informer")
	}
	log.Println("Pod cache synced successfully.")

	// eBPF setup
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		log.Printf("warning: setrlimit failed: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		log.Fatalf("failed to load eBPF spec: %v", err)
	}

	var objs struct {
		HandleExecve *ebpf.Program `ebpf:"handle_execve"`
		Events       *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.HandleExecve.Close()
	defer objs.Events.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}

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
				log.Println("ringbuf closed, exiting")
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		sourcePod := FindPodForPID(podCache, event.Pid, event.Ppid)
		comm := unix.ByteSliceToString(event.Comm[:])

		// parse args: args are concatenated null-terminated strings in ArgsBuf
		argBytes := event.ArgsBuf[:]
		var args []string
		start := 0
		for i := 0; i < len(argBytes) && len(args) < int(event.ArgsCount); i++ {
			if argBytes[i] == 0 {
				if i > start {
					args = append(args, string(argBytes[start:i]))
				}
				start = i + 1
			}
		}
		fullCommand := strings.Join(args, " ")

		enriched := EnrichedEvent{
			PID:         event.Pid,
			Comm:        comm,
			FullCommand: fullCommand,
			Pod:         sourcePod,
			NodeName:    nodeName,
		}

		if msg := checkRules(enriched); msg != "" {
			log.Printf("🚨 ALERT 🚨: %s triggered (pid=%d comm=%s pod=%v)", msg, enriched.PID, enriched.Comm, func() string {
				if enriched.Pod == nil {
					return "host"
				}
				return fmt.Sprintf("%s/%s", enriched.Pod.Namespace, enriched.Pod.Name)
			}())
			go sendSlackAlert(msg, enriched)
		}
	}
}
