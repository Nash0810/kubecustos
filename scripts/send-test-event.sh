#!/usr/bin/env bash
set -euo pipefail

# Simple script to POST a simulated EnrichedEvent to the backend
# Usage: BACKEND_URL=http://localhost:8080 ./scripts/send-test-event.sh

BACKEND_URL=${BACKEND_URL:-http://localhost:8080}

cat <<EOF | curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST -H "Content-Type: application/json" -d @- "$BACKEND_URL/api/v1/events"
{
  "pid": 1234,
  "ppid": 1,
  "comm": "xmrig",
  "full_command": "/tmp/xmrig --donate 1",
  "pod_name": "test-pod",
  "namespace": "default",
  "node_name": "node1",
  "container_id": "abcdef123456",
  "host_process": false,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "Posted test event to ${BACKEND_URL}/api/v1/events"
