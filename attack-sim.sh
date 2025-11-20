#!/bin/bash
set -e

echo "================================================"
echo "  KubeCustos Attack Simulation Script"
echo "================================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

wait_for_pod() {
    local pod_name=$1
    local max_wait=40
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

cleanup_pod() {
    local pod_name=$1
    kubectl delete pod $pod_name --wait=false 2>/dev/null || true
}

echo "${YELLOW}[Test 1/3]${NC} Crypto Miner Detection"
kubectl delete pod xmrig-test 2>/dev/null || true
sleep 2

kubectl run xmrig-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        # Create fake xmrig executable
        echo -e "#!/bin/sh\nsleep 60" > /tmp/xmrig
        chmod +x /tmp/xmrig

        /tmp/xmrig &
        sleep 45
    '

wait_for_pod "xmrig-test"
echo "Waiting 15 seconds for alert..."
sleep 15
cleanup_pod "xmrig-test"
echo ""

echo "${YELLOW}[Test 2/3]${NC} Supply Chain Attack Detection"
kubectl delete pod curl-bash-test 2>/dev/null || true
sleep 2

kubectl run curl-bash-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        apk add --no-cache curl >/dev/null 2>&1
        echo -e "#!/bin/sh\necho simulated malicious script" > /tmp/script.sh
        chmod +x /tmp/script.sh
        curl -s file:///tmp/script.sh | bash
        sleep 45
    '

wait_for_pod "curl-bash-test"
echo "Waiting 15 seconds..."
sleep 15
cleanup_pod "curl-bash-test"
echo ""

echo "${YELLOW}[Test 3/3]${NC} Execution from /tmp"
kubectl delete pod tmp-exec-test 2>/dev/null || true
sleep 2

kubectl run tmp-exec-test \
    --image=alpine \
    --restart=Never \
    --command -- /bin/sh -c '
        echo -e "#!/bin/sh\necho Simulated malware" > /tmp/malware
        chmod +x /tmp/malware
        /tmp/malware
        sleep 45
    '

wait_for_pod "tmp-exec-test"
echo "Waiting 15 seconds..."
sleep 15
cleanup_pod "tmp-exec-test"
echo ""

echo "================================================"
echo "${GREEN}Attack simulation complete!${NC}"
echo "================================================"

