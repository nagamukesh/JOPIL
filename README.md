# JOPIL — Journey of Packets in Linux Kernel

Real-time packet flow visualization using XDP eBPF. Captures packets at the kernel's earliest hook point and displays live network flows in a terminal dashboard.

## Features

- **XDP eBPF** packet capture — fastest possible hook in the Linux kernel
- Bidirectional flow aggregation with protocol distribution
- Interactive TUI with sorting, filtering, and drill-down
- DNS query tracking and failure detection
- TCP connection state monitoring
- Real-time throughput sparklines and top talkers

## Quick Start

```bash
# Build
go build -o bin/jopil ./cmd/jopil

# Run (requires root for XDP)
sudo ./bin/jopil

# Specify interface
sudo ./bin/jopil -iface wlan0

# Verbose mode
sudo ./bin/jopil -verbose
```

## Requirements

- Linux kernel 5.8+ (for XDP + ring buffer support)
- Go 1.21+
- Root/sudo privileges
- clang (only if regenerating eBPF bytecode)

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-iface` | auto-detect | Network interface for XDP |
| `-timeout` | 5m | Flow idle timeout |
| `-packet-buffer` | 5000 | Packet history per flow (1000-50000) |
| `-log` | stderr | Log file path |
| `-verbose` | false | Verbose logging |

## Keyboard Controls

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `↑` `↓` | Navigate flows |
| `d` / `Enter` | Drill-down into flow |
| `Esc` | Back from drill-down |
| `s` | Cycle sort (bytes → packets → duration) |
| `f` | Filter by protocol |
| `p` | Pause/resume |
| `h` | Help |

## Project Structure

```
JOPIL/
├── bpf/packet.c              — XDP eBPF program (C)
├── cmd/jopil/main.go          — Entry point
├── internal/
│   ├── model/                 — Packet, flow, stats types
│   ├── monitor/
│   │   ├── monitor.go         — XDP loader + ring buffer reader
│   │   ├── aggregator.go      — Flow correlation engine
│   │   ├── ringbuffer.go      — Packet history ring buffer
│   │   └── bpf_bpfel.*        — Generated eBPF bindings
│   ├── parser/dns.go          — DNS packet parser
│   └── tui/dashboard.go       — Terminal UI (Bubbletea)
├── Makefile                   — eBPF build + bpf2go codegen
└── go.mod
```

## Regenerating eBPF Bytecode

Only needed if you modify `bpf/packet.c`:

```bash
make generate
```

This recompiles the C to BPF bytecode and regenerates the Go bindings via `bpf2go`.

## Troubleshooting

**No packets?** Run with `-verbose` and check `dmesg` for eBPF errors.

**XDP attach fails?** Some drivers (e.g. r8169) don't support native XDP. Check `ethtool -i <iface>` for driver info.

**Permission denied?** Must run as root: `sudo ./bin/jopil`.
