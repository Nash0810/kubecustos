ARCH := bpf
CC := clang
CFLAGS := -I./pkg/ebpf -I/usr/include -g -O2 -target $(ARCH) -c
BPF_OBJECT := ./pkg/ebpf/probe.o
BPF_SOURCE := ./pkg/ebpf/probe.c

all: $(BPF_OBJECT)
$(BPF_OBJECT): $(BPF_SOURCE)
	$(CC) $(CFLAGS) -o $(BPF_OBJECT) $(BPF_SOURCE)
clean:
	rm -f $(BPF_OBJECT)