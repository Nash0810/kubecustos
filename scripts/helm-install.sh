#!/usr/bin/env bash
set -euo pipefail

# Helm install helper for local dev
# Usage: ./scripts/helm-install.sh [--with-monitoring]

WITH_MONITORING=0
if [ "${1:-}" = "--with-monitoring" ]; then
  WITH_MONITORING=1
fi

echo "Adding Helm repos..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
helm repo add grafana https://grafana.github.io/helm-charts || true
helm repo update

if [ "$WITH_MONITORING" -eq 1 ]; then
  echo "Installing kube-prometheus-stack into monitoring namespace..."
  kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
  helm upgrade --install prometheus prometheus-community/kube-prometheus-stack -n monitoring
fi

echo "Installing KubeCustos chart..."
helm upgrade --install kubecustos ./kubecustos -f ./kubecustos/values.local.yaml

echo "Done. Run 'kubectl get all' and monitor pods in the default namespace." 
