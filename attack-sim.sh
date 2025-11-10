#!/bin/bash
set -e

echo "================================================"
echo "  KubeCustos Attack Simulation Script"
echo "  Testing Security Detection Rules"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to wait for pod to be running
wait_for_pod() {
    local pod_name=$1
    local max_wait=30
    local count=0
    
    echo -n "Waiting for pod ${pod_name} to start..."
    while [ $count -lt $max_wait ]; do
        status=$(kubectl get pod $pod_name -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
        if [ "$status" = "Running" ] || [ "$status" = "Succeeded" ]; then
            echo " ${GREEN}✓${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
        count=$((count + 1))
    done
    echo " ${RED}✗ (timeout)${NC}"
    return 1
}

# Function to cleanup pod
cleanup_pod() {
    local pod_name=$1
    echo "Cleaning up pod ${pod_name}..."
    kubectl delete pod $pod_name --wait=false 2>/dev/null || true
}

echo "${YELLOW}[Test 1/3]${NC} Crypto Miner Detection (xmrig)"
echo "Creating a fake 'xmrig' binary and executing it..."
echo ""

# Delete if exists from previous run
kubectl delete pod xmrig-test 2>/dev/null || true
sleep 2

# Create pod that will trigger crypto miner detection
kubectl run xmrig-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        # Create a fake xmrig binary
        cp /bin/sleep /tmp/xmrig
        chmod +x /tmp/xmrig
        
        # Execute it - this will trigger the alert
        /tmp/xmrig 60 &
        
        # Keep pod alive so collector can get metadata
        echo "Fake crypto miner running (PID: $!)"
        sleep 45
    '

wait_for_pod "xmrig-test"
echo "Waiting 8 seconds for alert to fire..."
sleep 8
cleanup_pod "xmrig-test"
echo ""

echo "---"
echo ""

echo "${YELLOW}[Test 2/3]${NC} Supply Chain Attack Detection (curl | bash)"
echo "Simulating a command injection with curl piped to bash..."
echo ""

kubectl delete pod curl-bash-test 2>/dev/null || true
sleep 2

kubectl run curl-bash-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        # Install curl
        apk add --no-cache curl >/dev/null 2>&1
        
        # Execute a curl | bash pattern (safe - just echoes)
        echo "#!/bin/sh" > /tmp/fake-script.sh
        echo "echo Simulated malicious script" >> /tmp/fake-script.sh
        chmod +x /tmp/fake-script.sh
        
        # This will trigger the alert - actual curl | bash pattern
        curl -s file:///tmp/fake-script.sh | bash
        
        # Keep pod alive
        sleep 45
    '

wait_for_pod "curl-bash-test"
echo "Waiting 8 seconds for alert to fire..."
sleep 8
cleanup_pod "curl-bash-test"
echo ""

echo "---"
echo ""

echo "${YELLOW}[Test 3/3]${NC} Execution from /tmp Detection"
echo "Creating and executing a binary from /tmp directory..."
echo ""

kubectl delete pod tmp-exec-test 2>/dev/null || true
sleep 2

kubectl run tmp-exec-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        # Create a malicious-looking script in /tmp
        cat > /tmp/malware << "EOF"
#!/bin/sh
echo "This is a simulated malware"
sleep 5
EOF
        chmod +x /tmp/malware
        
        # Execute it - this will trigger the alert
        /tmp/malware
        
        # Keep pod alive
        sleep 45
    '

wait_for_pod "tmp-exec-test"
echo "Waiting 8 seconds for alert to fire..."
sleep 8
cleanup_pod "tmp-exec-test"
echo ""

echo "================================================"
echo "${GREEN}Attack simulation complete!${NC}"
echo ""
echo "Expected Results:"
echo "  - 3 alerts should appear in your logs"
echo "  - 3 alerts should be sent to Slack"
echo "  - Pod names should show correctly (not 'host/host')"
echo ""
echo "Check your logs with:"
echo "  kubectl logs -l app=kubecustos-collector --tail=50"
echo "================================================"