# Tools
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all generate build run clean

all: generate build

# 1. Generate Go bindings from C code using bpf2go
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	cd internal/monitor && go generate

# 2. Build the Go binary
build: generate
	go build -o bin/packet-viz cmd/main.go

# 3. Run (Needs Root)
run: build
	sudo ./bin/packet-viz

clean:
	rm -f bin/packet-viz
	rm -f internal/monitor/*_bpf*.go
	rm -f internal/monitor/*.o