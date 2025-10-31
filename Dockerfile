# Stage 1: Build the eBPF object file
FROM alpine:latest AS bpf-builder
RUN apk add --no-cache clang llvm libbpf-dev make
WORKDIR /src
COPY pkg/ebpf/probe.c pkg/ebpf/vmlinux.h ./pkg/ebpf/
COPY Makefile ./
RUN make

# Stage 2: Build the Go binary
FROM golang:1.24-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Copy the pre-compiled eBPF object directly next to main.go
COPY --from=bpf-builder /src/pkg/ebpf/probe.o ./cmd/collector/
RUN CGO_ENABLED=0 go build -o /collector ./cmd/collector

# Stage 3: Final minimal image
FROM alpine:latest
COPY --from=go-builder /collector /usr/local/bin/collector
CMD ["collector"]