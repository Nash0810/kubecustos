package models

import (
	"time"
	// Removed unused k8s.io/api/core/v1 import
)

// EnrichedEvent mirrors the data sent from the collector.
type EnrichedEvent struct {
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	Comm        string `json:"comm"`
	FullCommand string `json:"full_command"`
	PodName     string `json:"pod_name"`
	Namespace   string `json:"namespace"`
	NodeName    string `json:"node_name"`
	ContainerID string `json:"container_id"`
	HostProcess bool   `json:"host_process"`
	Timestamp   time.Time `json:"timestamp"`
}

// Alert is the structure used for persistence in PostgreSQL.
type Alert struct {
	ID          int64      `json:"id"`
	RuleName    string     `json:"rule_name"`
	Severity    string     `json:"severity"`
	PodName     string     `json:"pod_name"`
	Namespace   string     `json:"namespace"`
	NodeName    string     `json:"node_name"`
	FullCommand string     `json:"full_command"`
	Timestamp   time.Time  `json:"timestamp"`
	EventID     int64      `json:"event_id"`
}

// --- Slack Payload Structures (CRITICALLY MISSING, now added) ---

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