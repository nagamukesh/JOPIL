# JOPIL (Journey Of Packet In Linux kernel) Packet Visualizer

**Platform Requirements**: Linux kernel 5.8+ with eBPF/XDP support  
**Implementation**: Go 1.21+ backend with eBPF kernel module

## Project Overview

JOPIL is a real-time network packet visualization and analysis system leveraging extended Berkeley Packet Filter (eBPF) and eXpress Data Path (XDP) technology for high-performance kernel-level packet capture. The system provides live monitoring of network traffic flows, protocol analysis, and statistical aggregation through a web-based dashboard and RESTful API.

## Technical Architecture

### Technology Stack

- **Kernel Module**: eBPF with XDP for wire-speed packet capture
- **Runtime**: Go 1.21+ with Cilium eBPF library
- **Build System**: bpf2go for CO-RE (Compile Once, Run Everywhere)
- **Frontend**: HTML5, JavaScript with Chart.js for data visualization
- **Inter-Process Communication**: Ring buffer (256 KB) for kernel-userspace event delivery
- **HTTP Server**: Custom Go implementation with WebSocket support
- **Network Communication**: REST API on port 5000, WebSocket for real-time updates

### System Components

**Kernel Space (eBPF Program)**
```
File: bpf/packet_probe.c
- Packet parsing at XDP level
- Protocol identification (TCP, UDP, ICMP)
- Per-flow statistics computation
- Ring buffer event submission
```

**Userspace Backend**
```
Files:
- cmd/main.go: Application entry point and initialization
- internal/monitor/monitor.go: eBPF program loading and attachment
- internal/api/server.go: HTTP server and WebSocket handler
- internal/model/event.go: Data structures and serialization
```

**Frontend**
```
File: web/templates/dashboard.html
- Real-time packet statistics display
- Network flow visualization
- Protocol distribution analysis
- Multi-CPU load distribution tracking
```

### Data Flow Architecture

```
Physical Interface (eth0/wlo1)
         |
         v
    XDP Program (BPF)
    - Packet parsing
    - Header extraction
    - Flow identification
         |
         v
    Ring Buffer (256 KB)
    - Kernel-to-userspace IPC
    - Event queuing
         |
         v
    Go Backend (monitor.go)
    - Event reader
    - Statistics aggregator
    - Flow tracker
         |
         v
    HTTP Server (5000)
    ├── REST API (/api/stats, /api/flows)
    └── WebSocket (/ws)
         |
         v
    Browser Dashboard
    - Real-time visualization
    - Flow monitoring
    - Statistics display
```

## Build and Compilation

### Prerequisites

- Linux kernel with eBPF support (5.8+)
- Go 1.21 or later
- LLVM/Clang for BPF compilation
- Standard build tools (make, gcc)

### Compilation Process

```bash
cd /home/mukesh/JOPIL/JOPIL-Golang
make clean
make build
```

The build process:
1. Compiles eBPF program with CO-RE support
2. Generates BPF bytecode and Go bindings
3. Links Go binary with embedded BPF objects
4. Produces self-contained `bin/packet-viz` executable

## Operation

### Prerequisites for Execution

- Root privileges (required for XDP attachment)
- Network interface to monitor
- Port 5000 available (configurable)

### Starting the Application

```bash
cd /home/mukesh/JOPIL/JOPIL-Golang
sudo ./bin/packet-viz
```

### Accessing the System

- Dashboard: http://localhost:5000
- REST API: http://localhost:5000/api/stats
- WebSocket endpoint: ws://localhost:5000/ws

## API Endpoints

### Statistics Endpoint
```
GET /api/stats
Response: JSON object containing packet counts, protocol distribution, flow statistics
```

### Flows Endpoint
```
GET /api/flows
Response: JSON array of active network flows with packet counts and byte statistics
```

### WebSocket Endpoint
```
WS /ws
Real-time streaming of packet events and statistics updates
```

## Monitored Metrics

- Total packets captured
- Per-protocol packet counts (TCP, UDP, ICMP)
- Per-CPU packet distribution
- Network flow identification (source IP, destination IP, port)
- Packet payload sizes
- Flow-level statistics (packet count, byte count)

## Performance Characteristics

**Tested Performance Metrics**
- Packet capture rate: 1600+ packets per test run
- Concurrent flows tracked: 6+
- Protocol coverage: TCP, UDP, ICMP
- CPU utilization: Distributed across available cores
- Memory overhead: Ring buffer bounded at 256 KB

## Troubleshooting

### Common Issues

**XDP Attachment Failure**: "device or resource busy"
- Root Cause: Previous XDP program remains attached to interface
- Resolution: Execute cleanup_and_run.sh or manually detach with ip link commands

**Port Conflict**: "address already in use"
- Resolution: Terminate existing process on port 5000 using lsof and kill

**No Packet Capture**: Zero packets reported
- Verification: Generate test traffic (ping, curl) to verify system function
- Debugging: Query API endpoint to confirm data collection

**Kernel Module Load Error**: Version mismatch or missing capabilities
- Resolution: Verify kernel version 5.8+, check eBPF support availability
- Verification: Test with /proc/sys/kernel/unprivileged_bpf_disabled

## Project Structure

```
/home/mukesh/JOPIL/JOPIL-Golang/
├── cmd/
│   └── main.go                     # Application entry point
├── internal/
│   ├── api/
│   │   └── server.go               # HTTP and WebSocket server
│   ├── monitor/
│   │   ├── monitor.go              # BPF loader and event reader
│   │   ├── bpf_bpfel_x86.go        # Generated BPF bindings
│   │   └── bpf_bpfel_x86.o         # Compiled BPF objects
│   └── model/
│       └── event.go                # Data structures and conversion
├── bpf/
│   ├── packet_probe.c              # eBPF XDP program
│   └── headers/
│       ├── common.h                # Common definitions
│       └── hasher.h                # Hash computation utilities
├── web/
│   └── templates/
│       └── dashboard.html          # Web dashboard interface
├── bin/
│   └── packet-viz                  # Compiled executable
├── Makefile                        # Build automation
├── go.mod                          # Go module dependencies
└── go.sum                          # Dependency checksums
```

## Requirements and Dependencies

### System Requirements
- Linux operating system
- eBPF-capable kernel (5.8 or later)
- XDP support in network driver
- Root or CAP_SYS_ADMIN privileges

### Software Dependencies
- Go 1.21 or higher
- LLVM/Clang toolchain
- libc development headers
- Standard POSIX development tools

## License and Attribution

This project implements packet capture and analysis using eBPF technology as documented in the Linux kernel eBPF subsystem.
