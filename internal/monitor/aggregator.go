package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mukesh/jopil/internal/model"
	"github.com/mukesh/jopil/internal/parser"
)

// FlowAggregator correlates packets into flows and tracks statistics
type FlowAggregator struct {
	flows             map[string]*model.Flow
	flowMutex         sync.RWMutex
	eventChan         <-chan *model.PacketEvent
	flowChan          chan *model.Flow
	flowTimeout       time.Duration
	stopChan          chan struct{}
	globalStats       *GlobalAggregatorStats
	droppedPackets    uint64
	packetBufferSize  int // Configurable history size per flow
}

// GlobalAggregatorStats holds global statistics
type GlobalAggregatorStats struct {
	TotalPackets   uint64
	TotalBytes     uint64
	DroppedPackets uint64
	LastUpdated    time.Time
}

// NewFlowAggregator creates a new flow aggregator
func NewFlowAggregator(eventChan <-chan *model.PacketEvent, flowTimeout time.Duration, packetBufferSize int) *FlowAggregator {
	if packetBufferSize < 1000 {
		packetBufferSize = 1000
	}
	if packetBufferSize > 50000 {
		packetBufferSize = 50000
	}
	return &FlowAggregator{
		flows:            make(map[string]*model.Flow),
		eventChan:        eventChan,
		flowChan:         make(chan *model.Flow, 100),
		flowTimeout:      flowTimeout,
		stopChan:         make(chan struct{}),
		packetBufferSize: packetBufferSize,
		globalStats: &GlobalAggregatorStats{
			LastUpdated: time.Now(),
		},
	}
}

// Start begins the flow aggregation loop
func (fa *FlowAggregator) Start(ctx context.Context) {
	go fa.aggregateLoop(ctx)
	go fa.timeoutLoop(ctx)
}

// Stop stops the aggregator
func (fa *FlowAggregator) Stop() {
	close(fa.stopChan)
}

// Flows returns the channel of flows
func (fa *FlowAggregator) Flows() <-chan *model.Flow {
	return fa.flowChan
}

// GetAllFlows returns a snapshot of all current flows
func (fa *FlowAggregator) GetAllFlows() []*model.Flow {
	fa.flowMutex.RLock()
	defer fa.flowMutex.RUnlock()

	flows := make([]*model.Flow, 0, len(fa.flows))
	for _, flow := range fa.flows {
		flows = append(flows, flow)
	}
	return flows
}

// GetGlobalStats returns current global statistics
func (fa *FlowAggregator) GetGlobalStats() *model.GlobalStats {
	fa.flowMutex.RLock()
	defer fa.flowMutex.RUnlock()

	lossRate := 0.0
	if fa.globalStats.TotalPackets > 0 {
		lossRate = float64(fa.globalStats.DroppedPackets) / float64(fa.globalStats.TotalPackets+fa.globalStats.DroppedPackets)
	}

	return &model.GlobalStats{
		TotalPackets:   fa.globalStats.TotalPackets,
		TotalBytes:     fa.globalStats.TotalBytes,
		TotalFlows:     uint64(len(fa.flows)),
		DroppedPackets: fa.globalStats.DroppedPackets,
		PacketLossRate: lossRate,
		UpstreamTime:   fa.globalStats.LastUpdated,
		CurrentTime:    time.Now(),
	}
}

// aggregateLoop processes incoming packet events
func (fa *FlowAggregator) aggregateLoop(ctx context.Context) {
	defer func() {
		recover()
	}()

	for {
		select {
		case <-fa.stopChan:
			return
		case <-ctx.Done():
			return
		case evt := <-fa.eventChan:
			if evt != nil {
				fa.processEvent(evt)
			} else {
				// Channel closed
				return
			}
		}
	}
}

// processEvent processes a single packet event
func (fa *FlowAggregator) processEvent(evt *model.PacketEvent) {
	// Prepare data BEFORE acquiring lock (minimize critical section)
	srcIP := model.IPFromUint32(evt.Saddr)
	dstIP := model.IPFromUint32(evt.Daddr)
	protocol := model.ProtocolName(evt.Protocol)
	now := time.Now()
	
	// Create packet record BEFORE lock
	record := &model.PacketRecord{
		Timestamp:  now,
		SrcIP:      srcIP,
		SrcPort:    evt.Sport,
		DstIP:      dstIP,
		DstPort:    evt.Dport,
		Length:     evt.Len,
		Direction:  "forward", // Will update after determining direction
		TCPFlags:   evt.Protocol,
	}
	
	// Parse DNS BEFORE lock (this is the slow operation)
	var dnsQuery *model.DNSQuery
	var dnsQueries []*model.DNSQuery
	var dnsQueryNames map[string]uint64
	if evt.Protocol == 17 && evt.Dport == 53 && len(evt.Payload) > 0 { // UDP
		dnsResp := parser.ParseDNS(evt.Payload)
		if dnsResp != nil && len(dnsResp.Questions) > 0 {
			for _, q := range dnsResp.Questions {
				dq := &model.DNSQuery{
					Timestamp:    now,
					Domain:       q.Name,
					QueryType:    parser.GetQueryType(q.Type),
					IsResponse:   dnsResp.IsResponse,
					ResponseCode: parser.GetResponseCode(dnsResp.ResponseCode),
					Direction:    record.Direction,
				}
				dnsQuery = dq
				dnsQueries = append(dnsQueries, dq)
				if dnsQueryNames == nil {
					dnsQueryNames = make(map[string]uint64)
				}
				dnsQueryNames[q.Name]++
			}
			record.DNSQuery = dnsQuery
		}
	}
	
	// NOW acquire lock for minimal time
	fa.flowMutex.Lock()
	defer fa.flowMutex.Unlock()

	// Update global stats
	fa.globalStats.TotalPackets++
	fa.globalStats.TotalBytes += uint64(evt.Len)
	fa.globalStats.LastUpdated = now

	// Create flow key at conversation level
	flowKey := fa.getFlowKey(evt)

	// Get or create flow
	flow, exists := fa.flows[flowKey]
	if !exists {
		flow = &model.Flow{
			SrcIP:           srcIP,
			DstIP:           dstIP,
			Protocol:        protocol,
			FirstPacketTime: now,
			State:           "new",
			SrcPorts:        make(map[uint16]uint64),
			DstPorts:        make(map[uint16]uint64),
			PacketHistory:   model.NewRingBuffer(fa.packetBufferSize),
			StateChanges:    make([]*model.TCPStateChange, 0),
			DNSQueries:      make([]*model.DNSQuery, 0),
			DNSQueryNames:   make(map[string]uint64),
		}
		fa.flows[flowKey] = flow
	}

	// Determine direction: forward (src->dst) or reverse (dst->src)
	saddr_uint := evt.Saddr
	daddr_uint := evt.Daddr
	srcip_uint := model.IPToUint32(flow.SrcIP)
	dstip_uint := model.IPToUint32(flow.DstIP)
	isForward := saddr_uint == srcip_uint && daddr_uint == dstip_uint
	
	if !isForward {
		record.Direction = "reverse"
	}

	// Update flow statistics
	flow.LastPacketTime = now
	flow.PacketCount++
	flow.ByteCount += uint64(evt.Len)

	// Track directional stats
	if isForward {
		flow.ForwardPackets++
		flow.ForwardBytes += uint64(evt.Len)
	} else {
		flow.ReversePackets++
		flow.ReverseBytes += uint64(evt.Len)
	}

	// Track port usage
	flow.SrcPorts[evt.Sport]++
	flow.DstPorts[evt.Dport]++

	// Update top ports
	if flow.SrcPorts[evt.Sport] > flow.SrcPorts[flow.TopSrcPort] {
		flow.TopSrcPort = evt.Sport
	}
	if flow.DstPorts[evt.Dport] > flow.DstPorts[flow.TopDstPort] {
		flow.TopDstPort = evt.Dport
	}

	// Add packet to history (O(1) operation)
	flow.PacketHistory.Add(record)

	// Add DNS queries if present
	if len(dnsQueries) > 0 {
		flow.DNSQueries = append(flow.DNSQueries, dnsQueries...)
		for domain, count := range dnsQueryNames {
			flow.DNSQueryNames[domain] += count
		}
		flow.DNSLastQuery = now
		// Count DNS failures
		for _, q := range dnsQueries {
			if q.IsResponse && q.ResponseCode != "NoError" && q.ResponseCode != "" {
				flow.DNSFailures++
			}
		}
	}

	// Update TCP state if applicable
	if evt.Protocol == 6 { // TCP
		flow.TCPFlags = evt.Protocol
		oldState := flow.State
		
		// TCP state transitions based on packet count
		if flow.PacketCount == 1 {
			flow.State = "syn"
		} else if flow.PacketCount == 2 {
			flow.State = "syn-ack"
		} else if flow.PacketCount >= 3 {
			flow.State = "established"
		}
		
		// Track state changes
		if oldState != flow.State && len(flow.StateChanges) < 100 {
			stateChange := &model.TCPStateChange{
				Timestamp:   now,
				OldState:    oldState,
				NewState:    flow.State,
				Description: fmt.Sprintf("%s -> %s (packet %d)", oldState, flow.State, flow.PacketCount),
			}
			flow.StateChanges = append(flow.StateChanges, stateChange)
		}
	}
}

// getFlowKey creates a unique flow key from packet event
// Uses conversation-level grouping: (SrcIP, DstIP, Protocol)
// BIDIRECTIONAL: Normalizes key so A↔B and B↔A use the same key
// This ensures bidirectional flows are aggregated together
func (fa *FlowAggregator) getFlowKey(evt *model.PacketEvent) string {
	// Create a unique identifier at conversation level
	// Sort IPs so that both directions map to the same key
	srcIP := model.IPFromUint32(evt.Saddr).String()
	dstIP := model.IPFromUint32(evt.Daddr).String()
	proto := model.ProtocolName(evt.Protocol)
	
	// Normalize: always put smaller IP first so A↔B and B↔A match
	// This allows bidirectional flows to aggregate correctly
	if srcIP > dstIP {
		srcIP, dstIP = dstIP, srcIP
	}
	
	return fmt.Sprintf("%s-%s-%s", srcIP, dstIP, proto)
}

// uint16ToString converts uint16 to string
func (fa *FlowAggregator) uint16ToString(u uint16) string {
	return string(rune(u))
}

// timeoutLoop periodically closes idle flows
func (fa *FlowAggregator) timeoutLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fa.stopChan:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			fa.closeIdleFlows()
		}
	}
}

// closeIdleFlows removes flows that haven't seen activity
func (fa *FlowAggregator) closeIdleFlows() {
	fa.flowMutex.Lock()
	defer fa.flowMutex.Unlock()

	now := time.Now()
	toDelete := make([]string, 0)

	for key, flow := range fa.flows {
		if now.Sub(flow.LastPacketTime) > fa.flowTimeout {
			flow.State = "closed"
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(fa.flows, key)
	}
}
