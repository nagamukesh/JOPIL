//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" bpf ../../bpf/packet.c -- -I/usr/include/bpf -I/usr/include

package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mukesh/jopil/internal/model"
)

// StatusLog holds recent status messages for the TUI to display
type StatusLog struct {
	mu       sync.Mutex
	messages []StatusMessage
	maxSize  int
}

type StatusMessage struct {
	Time    time.Time
	Level   string // "info", "warn", "error"
	Message string
}

func NewStatusLog(maxSize int) *StatusLog {
	return &StatusLog{
		messages: make([]StatusMessage, 0, maxSize),
		maxSize:  maxSize,
	}
}

func (sl *StatusLog) Add(level, msg string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.messages = append(sl.messages, StatusMessage{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
	})
	if len(sl.messages) > sl.maxSize {
		sl.messages = sl.messages[1:]
	}
}

func (sl *StatusLog) Info(msg string)  { sl.Add("info", msg) }
func (sl *StatusLog) Warn(msg string)  { sl.Add("warn", msg) }
func (sl *StatusLog) Error(msg string) { sl.Add("error", msg) }
func (sl *StatusLog) Infof(format string, args ...interface{}) {
	sl.Add("info", fmt.Sprintf(format, args...))
}
func (sl *StatusLog) Warnf(format string, args ...interface{}) {
	sl.Add("warn", fmt.Sprintf(format, args...))
}
func (sl *StatusLog) Errorf(format string, args ...interface{}) {
	sl.Add("error", fmt.Sprintf(format, args...))
}

func (sl *StatusLog) GetRecent(n int) []StatusMessage {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if n > len(sl.messages) {
		n = len(sl.messages)
	}
	result := make([]StatusMessage, n)
	copy(result, sl.messages[len(sl.messages)-n:])
	return result
}

type EventReader struct {
	objs       *bpfObjects
	xdpLink    link.Link
	ringReader *ringbuf.Reader
	eventsChan chan *model.PacketEvent
	stopChan   chan struct{}
	iface      *net.Interface
	verbose    bool
	droppedInUserspace uint64
	Status     *StatusLog
}

// NewEventReader loads the embedded eBPF program and attaches XDP to the given interface.
func NewEventReader(ifaceName string, verbose bool) (*EventReader, error) {
	status := NewStatusLog(100)

	// Remove RLIMIT_MEMLOCK
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Find the target interface
	var iface *net.Interface
	var err error
	if ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
		}
	} else {
		iface, err = findPrimaryInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
	}

	status.Infof("Target interface: %s (index %d)", iface.Name, iface.Index)

	// Load compiled eBPF objects
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	status.Info("eBPF objects loaded")

	// Attach XDP program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProbeFunc,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach XDP to %s: %w", iface.Name, err)
	}

	status.Infof("XDP attached to %s", iface.Name)

	// Open ring buffer reader
	ringReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		xdpLink.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	status.Info("Ring buffer reader opened — capturing packets")

	// Log to stderr ONLY before TUI starts (these are pre-TUI startup messages)
	fmt.Fprintf(os.Stderr, "[JOPIL] XDP attached to %s — starting TUI\n", iface.Name)

	return &EventReader{
		objs:       &objs,
		xdpLink:    xdpLink,
		ringReader: ringReader,
		eventsChan: make(chan *model.PacketEvent, 10000),
		stopChan:   make(chan struct{}),
		iface:      iface,
		verbose:    verbose,
		Status:     status,
	}, nil
}

func (er *EventReader) Start() {
	go er.readLoop()
	go er.interfaceWatcherLoop()
}

func (er *EventReader) Events() <-chan *model.PacketEvent {
	return er.eventsChan
}

func (er *EventReader) Close() {
	close(er.stopChan)

	if er.ringReader != nil {
		er.ringReader.Close()
	}
	if er.xdpLink != nil {
		er.xdpLink.Close()
	}
	if er.objs != nil {
		er.objs.Close()
	}
}

// KernelStats returns the raw packet and byte counters from the kernel.
func (er *EventReader) KernelStats() (packets uint64, bytes uint64) {
	if er.objs == nil {
		return 0, 0
	}

	key := uint32(0)
	var stats bpfKernelStats

	if err := er.objs.PacketCountMap.Lookup(&key, &stats); err != nil {
		return 0, 0
	}

	return stats.Packets, stats.Bytes
}

func (er *EventReader) readLoop() {
	er.Status.Info("Read loop started")

	for {
		select {
		case <-er.stopChan:
			return
		default:
		}

		record, err := er.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if er.verbose {
				er.Status.Warnf("Read error: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		evt, err := parsePacketEvent(record.RawSample)
		if err != nil {
			er.Status.Warnf("Parse error: %v", err)
			continue
		}

		select {
		case er.eventsChan <- evt:
		case <-er.stopChan:
			return
		default:
			atomic.AddUint64(&er.droppedInUserspace, 1)
			er.Status.Warnf("Channel full, dropped event")
		}
	}
}

func (er *EventReader) interfaceWatcherLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastUp := true

	for {
		select {
		case <-er.stopChan:
			return
		case <-ticker.C:
			iface, err := net.InterfaceByName(er.iface.Name)
			if err != nil {
				er.Status.Warnf("Interface %s lookup failed: %v", er.iface.Name, err)
				continue
			}

			isUp := iface.Flags&net.FlagUp != 0
			if isUp != lastUp {
				if isUp {
					er.Status.Infof("Interface %s is UP", er.iface.Name)
				} else {
					er.Status.Warnf("Interface %s is DOWN — capture paused", er.iface.Name)
				}
				lastUp = isUp
			}
		}
	}
}

func parsePacketEvent(data []byte) (*model.PacketEvent, error) {
	const expectedSize = 36 // Exact size of fields without trailing padding
	if len(data) < expectedSize {
		return nil, fmt.Errorf("short sample: got %d bytes, want %d", len(data), expectedSize)
	}

	evt := &model.PacketEvent{}
	r := bytes.NewReader(data)

	var raw struct {
		TimestampNs  uint64
		Saddr        uint32
		Daddr        uint32
		Sport        uint16
		Dport        uint16
		Protocol     uint8
		Pad1         uint8
		Pad2         uint16
		Len          uint32
		CpuId        uint32
		QueueMapping uint16
		Pad3         uint16
	}

	if err := binary.Read(r, binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("binary.Read: %w", err)
	}

	evt.TimestampNs = raw.TimestampNs
	evt.Saddr = raw.Saddr
	evt.Daddr = raw.Daddr
	evt.Sport = raw.Sport
	evt.Dport = raw.Dport
	evt.Protocol = raw.Protocol
	evt.Len = raw.Len
	evt.CpuId = raw.CpuId
	evt.QueueMapping = raw.QueueMapping

	return evt, nil
}

func findPrimaryInterface() (*net.Interface, error) {
	preferred := []string{"eth0", "eno1", "ens3", "enp0s3", "wlan0", "wlo1"}

	for _, name := range preferred {
		iface, err := net.InterfaceByName(name)
		if err == nil && iface.Flags&net.FlagUp != 0 {
			return iface, nil
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 &&
			iface.Flags&net.FlagLoopback == 0 {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}
