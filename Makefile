# eBPF packet capture program Makefile

CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip

# Target architecture
ARCH ?= x86

# Output directory
OUTPUT := internal/monitor

# Source files
EBPF_SRC := bpf/packet.c

all: ebpf generate

.PHONY: ebpf
ebpf: $(OUTPUT)/bpf_bpfel_x86.o

$(OUTPUT)/bpf_bpfel_x86.o: $(EBPF_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) -O2 -target bpf -I/usr/include/bpf -c $(EBPF_SRC) -o $@
	$(STRIP) -g $@

.PHONY: generate
generate: $(OUTPUT)/bpf_bpfel_x86.o
	@echo "Generating Go bindings with bpf2go..."
	cd $(OUTPUT) && GOPACKAGE=monitor go run github.com/cilium/ebpf/cmd/bpf2go -type packet_event \
		-target amd64 \
		bpf ../../bpf/packet.c

.PHONY: clean
clean:
	rm -f $(OUTPUT)/bpf_bpfel_*.{o,go}
	rm -f *.o

help:
	@echo "eBPF Packet Capture Build"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Compile eBPF bytecode (default)"
	@echo "  generate  - Generate Go bindings from eBPF"
	@echo "  clean     - Remove generated files"
	@echo "  help      - Show this help message"
