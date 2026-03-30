package model

import (
	"net"
	"time"
)

// PacketEvent represents a single packet captured from the kernel
type PacketEvent struct {
	TimestampNs  uint64
	Hash         uint32
	Saddr        uint32
	Daddr        uint32
	Sport        uint16
	Dport        uint16
	Protocol     uint8
	ProbePoint   uint8
	Pad1         uint16
	Len          uint32
	CpuId        uint32
	QueueMapping uint16
	Pad2         uint16
	
	// Optional payload for protocol-specific parsing (DNS, HTTP, etc.)
	Payload []byte // Raw packet payload (not captured in real eBPF, but useful for testing)
}

// DNSQuery represents a single DNS query/response event
type DNSQuery struct {
	Timestamp  time.Time
	Domain     string // Domain name queried
	QueryType  string // "A", "AAAA", "CNAME", "MX", "TXT", etc.
	IsResponse bool   // True if this is a response (not a query)
	ResponseCode string // "NoError", "NXDomain", etc. (only for responses)
	Direction  string // "forward" (query) or "reverse" (response)
}

// PacketRecord represents a single packet in a flow (for drill-down view)
type PacketRecord struct {
	Timestamp  time.Time
	SrcIP      net.IP
	SrcPort    uint16
	DstIP      net.IP
	DstPort    uint16
	Length     uint32
	Direction  string // "forward" or "reverse"
	TCPFlags   uint8
	DNSQuery   *DNSQuery // Non-nil if this packet contains DNS data
}

// TCPStateChange represents a TCP state transition event
type TCPStateChange struct {
	Timestamp time.Time
	OldState  string
	NewState  string
	Description string
}

// Flow represents a bidirectional network conversation (src_ip -> dst_ip)
// Groups all packets between two IPs regardless of port variations
// This prevents table explosion while showing actual network conversations
type Flow struct {
	// 3-tuple identification (conversation level)
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     string // "tcp", "udp", "icmp", etc.

	// Port tracking (for debugging, shows which ports were used)
	SrcPorts     map[uint16]uint64 // src_port -> packet count
	DstPorts     map[uint16]uint64 // dst_port -> packet count
	TopSrcPort   uint16            // Most common source port
	TopDstPort   uint16            // Most common dest port

	// Stats
	PacketCount     uint64
	ByteCount       uint64
	LastPacketTime  time.Time
	FirstPacketTime time.Time

	// Direction tracking (for bidirectional flows)
	ForwardPackets  uint64
	ForwardBytes    uint64
	ReversePackets  uint64
	ReverseBytes    uint64

	// TCP specific
	TCPFlags       uint8
	TCPRetransmits uint32
	TCPOutOfOrder  uint32

	// State
	State string // "new", "established", "closing", "closed"
	
	// Packet history for drill-down view (O(1) circular ring buffer)
	PacketHistory *RingBuffer // Fixed-capacity circular buffer
	
	// TCP state changes for timeline view
	StateChanges   []*TCPStateChange

	// DNS specific (for UDP:53 flows)
	DNSQueries     []*DNSQuery // All DNS queries/responses in this flow
	DNSQueryNames  map[string]uint64 // Domain -> query count
	DNSFailures    uint64 // Count of failed DNS queries (NXDomain, ServFail, etc.)
	DNSLastQuery   time.Time // Timestamp of last DNS query
}

// FlowKey uniquely identifies a flow (unidirectional)
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// ReverseFlowKey returns the reverse flow key for bidirectional matching
func (k FlowKey) ReverseFlowKey() FlowKey {
	return FlowKey{
		SrcIP:    k.DstIP,
		DstIP:    k.SrcIP,
		SrcPort:  k.DstPort,
		DstPort:  k.SrcPort,
		Protocol: k.Protocol,
	}
}

// IPFromUint32 converts a uint32 to net.IP (accounting for little-endian deserialization of network byte order)
func IPFromUint32(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// IPToUint32 converts net.IP to uint32 (assumes IPv4)
func IPToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// ProtocolName converts protocol number to string
func ProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 2:
		return "igmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 41:
		return "ipv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 88:
		return "eigrp"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	default:
		return "other"
	}
}
