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

	// Existing KubeCustos packages
	"github.com/nash0810/kubecustos/pkg/k8s" 
	// NEW: Import the shared models package for event structure
	"github.com/nash0810/kubecustos/pkg/models" 
	"k8s.io/client-go/tools/clientcmd" // CRITICAL for local fallback
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:embed probe.o
var bpfObject []byte

// bpfEvent must exactly match the C struct emitted by the probe
type bpfEvent struct {
	Pid       uint32
	Ppid      uint32
	Comm      [16]byte
	ArgsBuf   [4096]byte
	ArgsCount int32
}

// LocalEventContext holds data required for local enrichment before forwarding.
type LocalEventContext struct {
	PID         uint32
	PPID        uint32
	Comm        string
	FullCommand string
	Pod         *v1.Pod
	NodeName    string
}

// Debug toggle via env var DEBUG=1
var debugEnabled bool

func dbg(format string, a ...interface{}) {
	if debugEnabled {
		log.Printf("[DEBUG] "+format, a...)
	}
}

// Regex to extract container ID from CRI-O cgroup paths
var cgroupRegex = regexp.MustCompile(`crio-([a-f0-9]{64})\.scope`) 

// pidCache caches pid -> containerID (or "" for host)
var (
	pidCache = make(map[uint32]string)
	pidLock  = sync.RWMutex{}
)

// getContainerIDFromPID reads /host/proc/PID/cgroup and extracts the container ID
func getContainerIDFromPID(pid uint32) (string, bool) {
	pidLock.RLock()
	if cid, ok := pidCache[pid]; ok {
		pidLock.RUnlock()
		dbg("pidCache HIT pid=%d cid=%q", pid, cid)
		return cid, true
	}
	pidLock.RUnlock()

	cgroupPath := fmt.Sprintf("/host/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		dbg("could not read cgroup for pid=%d: %v", pid, err)
		return "", false
	}

	txt := string(content)
	if matches := cgroupRegex.FindStringSubmatch(txt); len(matches) == 2 {
		cid := matches[1]
		pidLock.Lock()
		pidCache[pid] = cid
		pidLock.Unlock()
		dbg("extracted containerID=%s for pid=%d", cid, pid)
		return cid, true
	}

	// Not in a container (host process)
	pidLock.Lock()
	pidCache[pid] = ""
	pidLock.Unlock()
	dbg("pid=%d is a host process (no container id)", pid)
	return "", true
}

// FindPodForPID tries the PID first, then falls back to PPID
func FindPodForPID(podCache *k8s.PodCache, pid, ppid uint32) (string, *v1.Pod) {
	dbg("[FIND] resolving pod for pid=%d ppid=%d", pid, ppid)

	containerID, ok := getContainerIDFromPID(pid)
	if !ok {
		return "", nil
	}

	// Try parent PID if current PID is host
	if containerID == "" && ppid > 1 {
		dbg("[FIND] pid=%d is host; trying ppid=%d", pid, ppid)
		containerID, ok = getContainerIDFromPID(ppid)
		if !ok {
			return "", nil
		}
	}
	
	if containerID == "" {
		dbg("[FIND] pid=%d and ppid=%d resolved to host process", pid, ppid)
		return "", nil
	}

	dbg("[FIND] looking up Pod for containerID=%s", containerID)
	pod := podCache.FindPodByContainerID(containerID)
	if pod != nil {
		dbg("[FIND] resolved containerID=%s -> pod=%s/%s", containerID, pod.Namespace, pod.Name)
	} else {
		dbg("[FIND] containerID=%s -> no pod found (host or short-lived)", containerID)
	}
	return containerID, pod
}

// sendToBackend converts the enriched event and sends it via HTTP to the backend service.
func sendToBackend(event LocalEventContext, containerID string) {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		dbg("BACKEND_URL not set, skipping event forwarding.")
		return
	}

	// Prepare data for JSON serialization (using the shared models struct)
	podName, namespace := "host", "host"
	hostProcess := true
	if event.Pod != nil {
		podName = event.Pod.Name
		namespace = event.Pod.Namespace
		hostProcess = false
	}

	payload := models.EnrichedEvent{
		PID:         event.PID,
		PPID:        event.PPID,
		Comm:        event.Comm,
		FullCommand: event.FullCommand,
		PodName:     podName,
		Namespace:   namespace,
		NodeName:    event.NodeName,
		ContainerID: containerID,
		HostProcess: hostProcess,
		Timestamp:   time.Now().UTC(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal event JSON: %v", err)
		return
	}

	// Send event data to the backend's /api/v1/events endpoint
	resp, err := http.Post(backendURL+"/api/v1/events", "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send event to backend: %v", err)
	} else if resp.StatusCode != http.StatusAccepted {
		log.Printf("Backend rejected event (Status: %d)", resp.StatusCode)
	} else {
		dbg("Successfully forwarded event for pid=%d to backend", event.PID)
	}
}


// --- Main Function ---
func main() {
	// DEBUG env toggle
	debugEnabled = os.Getenv("DEBUG") == "1"
	if debugEnabled {
		log.Printf("[DEBUG] Debug logging ENABLED")
	} else {
		log.Printf("[INFO] Debug logging DISABLED")
	}

	log.Println("Starting KubeCustos Collector (Forwarding Mode)...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- CORRECTED KUBERNETES CLIENT SETUP ---
	log.Println("Attempting to load Kubernetes configuration...")
    
	var config *rest.Config
	var err error
	
	// 1. Try to load local kubeconfig file (via KUBECONFIG env or default path)
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	
	// 2. If local config fails, attempt to load in-cluster config (for final deployment)
	if err != nil {
		log.Printf("Warning: Failed to load local kubeconfig (%v). Falling back to in-cluster configuration...", err)
		config, err = rest.InClusterConfig()
		if err != nil {
			// If both fail, this is a fatal error
			log.Fatalf("Failed to get in-cluster config or local fallback: %v", err)
		}
	}
	log.Println("Successfully loaded Kubernetes configuration.")
    // --- END CORRECTED KUBERNETES CLIENT SETUP ---


	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create k8s clientset: %v", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable not set")
	}
	
	// Check BACKEND URL early
	if os.Getenv("BACKEND_URL") == "" {
		log.Fatal("BACKEND_URL environment variable not set. Cannot forward events.")
	}

	// Initialize and start the Informer-based pod cache
	log.Println("Starting Pod cache informer...")
	podCache := k8s.NewPodCache(clientset, nodeName)
	// Placeholder for k8s.SetDebug (assuming it exists in pkg/k8s)
	// k8s.SetDebug(debugEnabled) 

	if !podCache.Run(ctx) {
		log.Fatal("Failed to sync pod cache informer")
	}
	log.Println("Pod cache synced successfully.")

	// Setup eBPF
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	var objs struct {
		HandleExecve *ebpf.Program `ebpf:"handle_execve"`
		Events       *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
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
				log.Println("Ringbuf closed, exiting event loop.")
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		commStr := unix.ByteSliceToString(event.Comm[:])
		dbg("[EVENT] pid=%d ppid=%d comm=%s argsCount=%d", event.Pid, event.Ppid, commStr, event.ArgsCount)

		// Parse arguments
		argBytes := event.ArgsBuf[:]
		var args []string
		start := 0
		for i := 0; i < len(argBytes); i++ {
			if argBytes[i] == 0 {
				if i > start {
					args = append(args, string(argBytes[start:i]))
				}
				start = i + 1
				if len(args) >= int(event.ArgsCount) {
					break
				}
			}
		}
		fullCommand := strings.Join(args, " ")
		dbg("[EVENT] pid=%d parsed fullCommand=%q", event.Pid, fullCommand)

		// Look up Pod and get the raw Container ID
		containerID, sourcePod := FindPodForPID(podCache, event.Pid, event.Ppid)

		localEvent := LocalEventContext{
			PID:         event.Pid,
			PPID:        event.Ppid,
			Comm:        commStr,
			FullCommand: fullCommand,
			Pod:         sourcePod,
			NodeName:    nodeName,
		}

		// FORWARD EVENT TO BACKEND SERVICE
		go sendToBackend(localEvent, containerID)
	}
}