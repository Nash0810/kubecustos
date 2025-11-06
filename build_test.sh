#!/bin/bash
set -e

echo "🔧 Updating and installing dependencies..."
sudo apt update -y
sudo apt install -y clang llvm make git libbpf-dev linux-headers-$(uname -r)

# Ensure we’re using the latest Go
if ! go version | grep -q "go1.24"; then
  echo "⚠️  Go 1.24 not detected — installing..."
  wget -q https://go.dev/dl/go1.24.1.linux-arm64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.24.1.linux-arm64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  source ~/.bashrc
  go version
fi

echo "🏗️ Building eBPF object..."
clang -I./pkg/ebpf -I/usr/include -g -O2 -target bpf -c -o ./cmd/collector/probe.o ./pkg/ebpf/probe.c

echo "🚀 Building Go collector..."
cd cmd/collector
go build -o kubecustos-collector

echo "✅ Build successful!"
echo "➡️  Binary available at: $(pwd)/kubecustos-collector"

