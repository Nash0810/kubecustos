# KubeCustos — Iteration 1 (MVP: Falco‑Lite)

This repository implements a minimal eBPF → collector → backend security monitoring pipeline.

Iteration 1 goal (MVP): kernel eBPF probe → Go collector → backend rules engine → Slack alerts → Prometheus/Grafana visibility.

This README explains how to build and test the components locally and what remains to finish a full in-cluster end‑to‑end run.

Prerequisites
 - Go 1.20+ (or compatible)
 - clang/LLVM (for building eBPF object: `make build-ebpf`)
 - A Kubernetes cluster + kubectl for in-cluster testing (OKE recommended for final test)

Quick local developer flow

1) Build the eBPF probe object (required by the collector):

```bash
make build-ebpf
```

2) Run backend locally (no Postgres required — in-memory fallback):

```bash
# optional: export SLACK_WEBHOOK_URL to test Slack delivery
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
PORT=8080 go run ./cmd/backend
```

3) Send a test event to exercise rule engine / Slack path:

```bash
./scripts/send-test-event.sh
```

4) Run unit tests for backend rule engine:

```bash
go test ./cmd/backend -v
```

5) Build the collector binary (it embeds `pkg/ebpf/probe.o`):

```bash
go build ./cmd/collector
```

Notes about the Collector and eBPF
- The eBPF probe emits PID, PPID, comm, arguments, kernel cgroup inode id, UID and a kernel timestamp.
- The collector attempts to resolve container ID and Pod metadata by:
  1. Prefer kernel cgroup inode mapping (searching under /sys/fs/cgroup and caching results).
  2. Fallback to reading `/host/proc/<pid>/cgroup` and parsing container IDs (works with many runtimes).

On real nodes, the collector should be deployed as a DaemonSet with `hostPID: true` and appropriate RBAC to read Pod resources.

Helm / Deployment
- A Helm chart skeleton exists under `kubecustos/` — fill values for images, resources, and `SLACK_WEBHOOK_URL` secret.
- For the MVP you can remove Redis from the chart if you don't need it; it's not currently used by the backend.

Attack simulation
- `attack-sim.sh` contains three scenarios (crypto miner, curl|bash, /tmp exec). Run it against an in-cluster deployment to validate detection and Slack alerts.

What remains to complete Iteration 1 (in-cluster end-to-end)
- Deploy the Helm chart to an OKE cluster with privileged DaemonSet for collector.
- Ensure nodes have the bpf toolchain or build `probe.o` and bake it into the collector image.
- Confirm cgroup mapping works for your OCI runtime (containerd, CRI-O) and tune the collector mapping logic if needed.
- Deploy Prometheus and Grafana (kube-prometheus-stack recommended) and import dashboards.
- Run `attack-sim.sh` in-cluster and verify alerts in Slack and records in Postgres.

If you'd like, I can:
- Prepare Helm `values.yaml` for a sample OKE deployment.
- Generate a minimal Grafana dashboard JSON and a ServiceMonitor manifest for scraping `/metrics`.
- Implement an alternate, faster cgroup-id mapping approach for your node runtime if searching `/sys/fs/cgroup` is unreliable.

Local Helm helper
 - I added `kubecustos/values.local.yaml` with development values, and `scripts/helm-install.sh` to install the chart and optionally monitoring.
 - A Grafana dashboard (`kubecustos/dashboards/ebpf-dashboard.json`) and a ConfigMap Helm template (`kubecustos/templates/grafana-dashboard-configmap.yaml`) were added so Grafana sidecars can import the dashboard.


-- KubeCustos Team
