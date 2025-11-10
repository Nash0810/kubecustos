# --- Stage 1: Build the eBPF object file ---
FROM --platform=linux/arm64 alpine:latest AS bpf-builder
RUN apk add --no-cache clang llvm libbpf-dev make
WORKDIR /src
COPY pkg/ebpf/probe.c pkg/ebpf/vmlinux.h ./pkg/ebpf/
COPY Makefile ./
RUN make build-ebpf

# --- Stage 2: Build the Go binary ---
FROM --platform=linux/arm64 golang:1.24-alpine AS go-builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=bpf-builder /src/pkg/ebpf/probe.o ./cmd/collector/
RUN CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
    go build -o /collector ./cmd/collector

# --- Stage 3: Final minimal image ---
FROM --platform=linux/arm64 alpine:latest
RUN apk add --no-cache ca-certificates

COPY --from=go-builder /collector /usr/local/bin/collector

# The collector must run as root to load eBPF programs
CMD ["collector"]