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
	"strings"
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

func main() {
	log.Println("Starting KubeCustos Collector...")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	config, _ := rest.InClusterConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	nodeName := os.Getenv("NODE_NAME")

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

	go func() { <-stopper; log.Println("Received signal, exiting..."); rd.Close() }()

	log.Println("Probe attached. Waiting for events...")
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) { return }
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		pods, _ := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + nodeName})
		var sourcePod *v1.Pod
		if len(pods.Items) > 0 { sourcePod = &pods.Items[0] }

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