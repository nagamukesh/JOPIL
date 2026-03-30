package model

import (
	"sync"
	"unsafe"
)

// RingBuffer is a fixed-size circular buffer for packet records
// Optimized for high performance - no allocations after init, O(1) writes
type RingBuffer struct {
	packets  []*PacketRecord
	capacity int
	writeIdx int
	readIdx  int
	count    int
	mu       sync.Mutex
}

// NewRingBuffer creates a new ring buffer with fixed capacity
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		packets:  make([]*PacketRecord, capacity),
		capacity: capacity,
		writeIdx: 0,
		readIdx:  0,
		count:    0,
	}
}

// Add adds a packet to the ring buffer (overwrites oldest if full)
func (rb *RingBuffer) Add(pkt *PacketRecord) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.packets[rb.writeIdx] = pkt
	rb.writeIdx = (rb.writeIdx + 1) % rb.capacity

	if rb.count < rb.capacity {
		rb.count++
	} else {
		// Buffer is full, readIdx advances to skip oldest packet
		rb.readIdx = (rb.readIdx + 1) % rb.capacity
	}
}

// GetAll returns all packets in chronological order (newest last)
// Returns a copy of packet pointers, so caller can iterate without holding locks
func (rb *RingBuffer) GetAll() []*PacketRecord {
	rb.mu.Lock()
	count := rb.count
	readIdx := rb.readIdx
	capacity := rb.capacity
	// Copy packet references ONLY (not PacketRecord objects)
	packets := make([]*PacketRecord, len(rb.packets))
	copy(packets, rb.packets)
	rb.mu.Unlock()

	if count == 0 {
		return []*PacketRecord{}
	}

	result := make([]*PacketRecord, 0, count)
	
	// Iterate through captured packets starting from readIdx
	for i := 0; i < count; i++ {
		pos := (readIdx + i) % capacity
		if packets[pos] != nil {
			result = append(result, packets[pos])
		}
	}

	return result
}

// Len returns the number of packets in the buffer
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

// Clear empties the buffer
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.packets = make([]*PacketRecord, rb.capacity)
	rb.writeIdx = 0
	rb.readIdx = 0
	rb.count = 0
}

// MemorySize returns approximate memory usage in bytes
func (rb *RingBuffer) MemorySize() int {
	// Each pointer + bookkeeping
	ptrSize := int(unsafe.Sizeof((*PacketRecord)(nil)))
	return rb.capacity*ptrSize + 64 // 64 for other fields
}

// EstimateRingBufferSize estimates bytes needed for N packet records
func EstimateRingBufferSize(numFlows int, packetCapacity int) int {
	ptrSize := int(unsafe.Sizeof((*PacketRecord)(nil)))
	return numFlows * packetCapacity * ptrSize
}
