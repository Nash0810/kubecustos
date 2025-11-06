# --- Stage 1: Build the eBPF object file ---
FROM alpine:latest AS bpf-builder
RUN apk add --no-cache clang llvm libbpf-dev make
WORKDIR /src
COPY pkg/ebpf/probe.c pkg/ebpf/vmlinux.h ./pkg/ebpf/
COPY Makefile ./

# Explicitly run the 'build-ebpf' target from the Makefile
RUN make build-ebpf

# --- Stage 2: Build the Go binary ---
FROM golang:1.24-alpine AS go-builder
# Add C build tools needed for CGO
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Copy the pre-compiled eBPF object from stage 1
COPY --from=bpf-builder /src/pkg/ebpf/probe.o ./cmd/collector/

# --- FIXES ---
# 1. Set CGO_ENABLED=1 (required by cilium/ebpf)
# 2. Set GOOS=linux and GOARCH=arm64 explicitly
RUN CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
    go build -o /collector ./cmd/collector

# --- Stage 3: Final minimal image ---
FROM alpine:latest

# --- FIX ---
# 3. Add ca-certificates for HTTPS (K8s API, Slack)
RUN apk add --no-cache ca-certificates

COPY --from=go-builder /collector /usr/local/bin/collector

# Set a non-root user for better security
RUN adduser -D nonroot
USER nonroot

CMD ["collector"]