#!/usr/bin/env bash
set -euo pipefail

# Simple helper to build collector and backend images and push to registry.
# Usage: REGISTRY=registry.example.com TAG=v1 ./scripts/build-and-push.sh

REGISTRY=${REGISTRY:-}
TAG=${TAG:-latest}

if [ -z "$REGISTRY" ]; then
  echo "Please set REGISTRY (e.g. docker.io/youruser)"
  exit 1
fi

echo "Building eBPF object..."
make build-ebpf

echo "Building collector image"
docker build -f Dockerfile.collector -t ${REGISTRY}/kubecustos-collector:${TAG} .

echo "Building backend image"
docker build -f Dockerfile.backend -t ${REGISTRY}/kubecustos-backend:${TAG} .

echo "Pushing images"
docker push ${REGISTRY}/kubecustos-collector:${TAG}
docker push ${REGISTRY}/kubecustos-backend:${TAG}

echo "Done. Update kubecustos/values.local.yaml with repository names and use Helm to deploy."
