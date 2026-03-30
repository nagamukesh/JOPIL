package model

import (
	"time"
)

// GlobalStats holds overall traffic statistics
type GlobalStats struct {
	TotalPackets    uint64
	TotalBytes      uint64
	TotalFlows      uint64
	DroppedPackets  uint64
	PacketLossRate  float64
	UpstreamTime    time.Time
	CurrentTime     time.Time

	// Rates
	PacketsPerSec float64
	BytesPerSec   float64
	MbpsRate      float64
}

// InterfaceStats holds per-interface statistics
type InterfaceStats struct {
	Name        string
	BytesIn     uint64
	BytesOut    uint64
	PacketsIn   uint64
	PacketsOut  uint64
	ErrorsIn    uint32
	ErrorsOut   uint32
	DroppedIn   uint32
	DroppedOut  uint32
	LastUpdated time.Time
}
