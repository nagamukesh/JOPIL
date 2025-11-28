package model

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type PacketEvent struct {
	TimestampNs  uint64
	Hash         uint32
	SAddr        uint32
	DAddr        uint32
	SPort        uint16
	DPort        uint16
	Protocol     uint8
	ProbePoint   uint8
	Pad1         uint16
	Len          uint32
	CpuID        uint32
	QueueMapping uint16
	Pad2         uint16
}

func (e *PacketEvent) Decode(r io.Reader) error {
	return binary.Read(r, binary.LittleEndian, e)
}

func (e *PacketEvent) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":    float64(e.TimestampNs) / 1e9,
		"timestamp_ns": e.TimestampNs,
		"hash":         fmt.Sprintf("%08x", e.Hash),
		"src_ip":       intToIP(e.SAddr),
		"dst_ip":       intToIP(e.DAddr),
		"src_port":     swapUint16(e.SPort),
		"dst_port":     swapUint16(e.DPort),
		"protocol":     resolveProtocol(e.Protocol),
		"probe":        resolveProbe(e.ProbePoint),
		"len":          e.Len,
		"cpu":          e.CpuID,
		"queue":        e.QueueMapping,
	}
}

func swapUint16(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func intToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}

func resolveProtocol(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO-%d", p)
	}
}

func resolveProbe(p uint8) string {
	switch p {
	case 1:
		return "NIC-RX"
	case 2:
		return "IP-Receive"
	default:
		return fmt.Sprintf("PROBE-%d", p)
	}
}