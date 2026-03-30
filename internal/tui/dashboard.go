package tui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mukesh/jopil/internal/model"
	"github.com/mukesh/jopil/internal/monitor"
)

// ThroughputSample represents a point in time for throughput tracking
type ThroughputSample struct {
	Timestamp time.Time
	BytesPerSec   uint64
	PacketsPerSec uint64
}

// Dashboard represents the TUI dashboard
type Dashboard struct {
	aggregator     *monitor.FlowAggregator
	reader         *monitor.EventReader
	width          int
	height         int
	flows          []*model.Flow
	allFlows       []*model.Flow  // Unfiltered flows
	globalStats    *model.GlobalStats
	mainScroll     int  // Scroll position for main dashboard view
	paused         bool
	selectedFlow   int
	sortBy         string // "bytes", "packets", "duration", "latest"
	filterProto    string // "", "tcp", "udp", "icmp"
	lastUpdate     time.Time
	
	// Table scrolling
	tableScroll    int    // Scroll position for flows table
	
	// Drill-down view fields
	drillMode      bool   // Whether we're in drill-down view
	drillFlowIdx   int    // Index of flow being drilled into
	drillScroll    int    // Scroll position for entire drill-down view
	frozenFlows    []*model.Flow // Snapshot of flows when entering drill-down mode
	cachedPackets  []*model.PacketRecord // Cached packet history to avoid per-frame locks
	
	// Help dialog fields
	helpMode       bool   // Whether we're in help view
	
	// Filter dialog fields
	filterMode     bool   // Whether we're in filter mode
	filterInput    string // Current filter input
	availableProtos []string // List of available protocols
	
	// Selection tracking
	selectedFlowId string // Track selected flow by identity (srcIP|dstIP|proto) for sticky selection
	
	// Stats tracking for widgets
	throughputHistory []*ThroughputSample // Last 60 seconds of throughput data
	lastStatsTime     time.Time
	lastTotalPackets  uint64
	lastTotalBytes    uint64
}

// NewDashboard creates a new dashboard
func NewDashboard(aggregator *monitor.FlowAggregator, reader *monitor.EventReader) *Dashboard {
	now := time.Now()
	return &Dashboard{
		aggregator:    aggregator,
		reader:        reader,
		flows:         make([]*model.Flow, 0),
		allFlows:      make([]*model.Flow, 0),
		globalStats:   &model.GlobalStats{},
		mainScroll:    0,
		paused:        false,
		selectedFlow:  0,
		sortBy:        "bytes",
		filterProto:   "",
		lastUpdate:    now,
		availableProtos: []string{"", "tcp", "udp", "icmp", "ipv6", "igmp", "gre", "esp", "ah", "eigrp", "ospf", "sctp"},
		throughputHistory: make([]*ThroughputSample, 0, 60),
		lastStatsTime:    now,
		lastTotalPackets: 0,
		lastTotalBytes:   0,
	}
}

// Init initializes the dashboard
func (d *Dashboard) Init() tea.Cmd {
	return d.refreshFlows()
}

// Update handles updates to the dashboard
func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return d.handleKeypress(msg)
	case tea.MouseMsg:
		return d.handleMouseScroll(msg)
	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
		return d, nil
	case RefreshFlowsMsg:
		d.updateFlows()
		d.updateStats()
		return d, d.refreshFlows()
	}
	return d, nil
}

// View renders the dashboard
func (d *Dashboard) View() string {
	if d.width == 0 {
		return "Initializing..."
	}

	if d.helpMode {
		return d.renderHelp()
	}

	if d.filterMode {
		return d.renderFilterDialog()
	}

	if d.drillMode && d.drillFlowIdx < len(d.flows) {
		return d.renderDrillDown()
	}

	// Update stats for widgets
	d.updateThroughputHistory()

	// Build all content into lines for scrollable view
	allLines := []string{}

	// Header
	headerLines := splitLines(d.renderHeader())
	allLines = append(allLines, headerLines...)
	allLines = append(allLines, "")

	// Top widgets
	statsWidget := d.renderRealTimeStats()
	protoWidget := d.renderProtocolDistribution()
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, statsWidget, "  ", protoWidget)
	
	topLines := splitLines(topRow)
	allLines = append(allLines, topLines...)
	allLines = append(allLines, "")

	// Sparkline
	sparklineWidget := d.renderTrafficSparkline()
	sparkLines := splitLines(sparklineWidget)
	allLines = append(allLines, sparkLines...)
	allLines = append(allLines, "")

	// Main table
	table := d.renderFlowsTable()
	tableLines := splitLines(table)
	allLines = append(allLines, tableLines...)
	allLines = append(allLines, "")

	// Bottom widgets row 1: top talkers + port analyzer
	topTalkersWidget := d.renderTopTalkers()
	portAnalyzerWidget := d.renderPortAnalyzer()
	bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, topTalkersWidget, "  ", portAnalyzerWidget)
	
	bottomLines := splitLines(bottomRow)
	allLines = append(allLines, bottomLines...)
	allLines = append(allLines, "")

	// Status log widget
	statusWidget := d.renderStatusLog()
	statusLines := splitLines(statusWidget)
	allLines = append(allLines, statusLines...)
	allLines = append(allLines, "")

	// Footer
	footerLines := splitLines(d.renderFooter())
	allLines = append(allLines, footerLines...)

	// Apply scrolling
	availableRows := d.height
	if availableRows < 10 {
		availableRows = 10
	}

	// Handle scroll bounds
	maxScroll := len(allLines) - availableRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if d.mainScroll > maxScroll {
		d.mainScroll = maxScroll
	}

	// Render only visible lines
	visibleLines := allLines[d.mainScroll:]
	if len(visibleLines) > availableRows {
		visibleLines = visibleLines[:availableRows]
	}

	return lipgloss.JoinVertical(lipgloss.Left, visibleLines...)
}

// splitLines splits a multi-line string into individual lines
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// renderHeader renders the header section
func (d *Dashboard) renderHeader() string {
	title := "╔ JOPIL - Journey of Packet in Linux Kernel ════════════════════════════════╗"
	style := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39"))

	return style.Render(title)
}

// renderFlowsTable renders the flows table
func (d *Dashboard) renderFlowsTable() string {
	// Table header - showing bidirectional stats
	headerStr := fmt.Sprintf(
		"│ %-17s │ %-17s │ %-6s │ %7s | %7s │ %-8s │ %-12s",
		"SRC IP", "DST IP", "PROTO", "→ PKTS", "← PKTS", "TOTAL", "BYTES",
	)

	style := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("240")).
		PaddingLeft(1)

	lines := []string{
		style.Render("╭─────────────────┬─────────────────┬────────┬─────────┼─────────┬──────────┬──────────────╮"),
		style.Render(headerStr),
		style.Render("├─────────────────┼─────────────────┼────────┼─────────┼─────────┼──────────┼──────────────┤"),
	}

	// Calculate available rows (height - header - stats - blank lines - footer = ~5 lines overhead)
	availableRows := d.height - 12
	if availableRows < 3 {
		availableRows = 3
	}

	// Table rows
	if len(d.flows) == 0 {
		emptyRow := fmt.Sprintf("│ %-17s │ %-17s │ %-6s │ %7s | %7s │ %-8s │ %-12s",
			"(no flows)", "", "", "", "", "", "")
		lines = append(lines, style.Render(emptyRow))
	} else {
		// Cap displayed flows at 200 max to prevent render time growing with flow count
		displayFlows := d.flows
		if len(displayFlows) > 200 {
			displayFlows = displayFlows[:200]
		}

		// Ensure table scroll is valid
		if d.tableScroll > len(displayFlows) - availableRows {
			d.tableScroll = len(displayFlows) - availableRows
		}
		if d.tableScroll < 0 {
			d.tableScroll = 0
		}
		
		startIdx := d.tableScroll
		endIdx := startIdx + availableRows
		if endIdx > len(displayFlows) {
			endIdx = len(displayFlows)
		}
		
		for i := startIdx; i < endIdx; i++ {
			flow := displayFlows[i]
			prefix := "  "
			if i == d.selectedFlow {
				prefix = "▶ "
			}

			row := fmt.Sprintf(
				"│ %s%-15s │ %-17s │ %-6s │ %7d | %7d │ %-8d │ %-12s",
				prefix,
				flow.SrcIP.String(),
				flow.DstIP.String(),
				flow.Protocol,
				flow.ForwardPackets,
				flow.ReversePackets,
				flow.PacketCount,
				formatBytes(flow.ByteCount),
			)
			lines = append(lines, row)
		}
		
		// Show scroll indicators
		hiddenTop := d.tableScroll
		hiddenBottom := len(d.flows) - endIdx
		if hiddenTop > 0 || hiddenBottom > 0 {
			hiddenRow := fmt.Sprintf("│ %-73s [%d up, %d down] │", "", hiddenTop, hiddenBottom)
			lines = append(lines, style.Render(hiddenRow))
		}
	}

	lines = append(lines, style.Render("╰─────────────────┴─────────────────┴────────┴────────┴────────┴──────────┴──────────────╯"))
	lines = append(lines, style.Render("* Most common port (port_count if >1 variation)"))

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderFooter renders the footer with instructions
func (d *Dashboard) renderFooter() string {
	footer := fmt.Sprintf("[?]Help │ [P]ause │ [↑↓/KJ]Move │ [PgUp/PgDn]Scroll │ [Enter]Drill │ [F]ilter │ [S]ort: %s │ [Q]uit", d.sortBy)
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		PaddingLeft(1)

	return style.Render(footer)
}

// getStateEmoji returns a visual emoji representation for a TCP state
func getStateEmoji(state string) string {
	switch state {
	case "SYN_SENT", "SYN_RCVD":
		return "🔵" // Blue - initiating
	case "ESTABLISHED":
		return "🟢" // Green - active
	case "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "TIME_WAIT":
		return "🟡" // Yellow - closing
	case "CLOSED":
		return "🔴" // Red - closed
	default:
		return "⭕" // Gray - unknown
	}
}

// getStateColor returns a lipgloss color for a TCP state for better UX
func getStateColor(state string) lipgloss.Color {
	switch state {
	case "SYN_SENT", "SYN_RCVD":
		return lipgloss.Color("39") // Blue
	case "ESTABLISHED":
		return lipgloss.Color("46") // Green
	case "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "TIME_WAIT":
		return lipgloss.Color("220") // Yellow
	case "CLOSED":
		return lipgloss.Color("196") // Red
	default:
		return lipgloss.Color("250") // Gray
	}
}

// renderDrillDown renders the detailed view for a selected flow (two-column layout)
func (d *Dashboard) renderDrillDown() string {
	if d.drillFlowIdx >= len(d.frozenFlows) {
		return "Flow not found"
	}

	flow := d.frozenFlows[d.drillFlowIdx]
	
	// Calculate column widths
	totalWidth := d.width - 4 // Leave some margin
	leftColWidth := (totalWidth * 60) / 100
	rightColWidth := (totalWidth * 40) / 100
	if leftColWidth < 30 {
		leftColWidth = 30
	}
	if rightColWidth < 20 {
		rightColWidth = 20
	}

	// ===== RIGHT COLUMN: Fixed flow details =====
	rightLines := []string{}
	
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	rightLines = append(rightLines, headerStyle.Render(fmt.Sprintf("FLOW DETAILS")))
	rightLines = append(rightLines, "─────────────────")
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, fmt.Sprintf("Src: %s", flow.SrcIP.String()))
	rightLines = append(rightLines, fmt.Sprintf("Dst: %s", flow.DstIP.String()))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, fmt.Sprintf("Proto: %s", flow.Protocol))
	rightLines = append(rightLines, fmt.Sprintf("State: %s", flow.State))
	rightLines = append(rightLines, fmt.Sprintf("Dur: %s", formatDuration(flow.LastPacketTime.Sub(flow.FirstPacketTime))))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, fmt.Sprintf("Packets: %d", flow.PacketCount))
	rightLines = append(rightLines, fmt.Sprintf("→ %d | ← %d", flow.ForwardPackets, flow.ReversePackets))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, fmt.Sprintf("Bytes: %s", formatBytes(flow.ByteCount)))
	rightLines = append(rightLines, fmt.Sprintf("→ %s", formatBytes(flow.ForwardBytes)))
	rightLines = append(rightLines, fmt.Sprintf("← %s", formatBytes(flow.ReverseBytes)))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, fmt.Sprintf("Src Port: %d", flow.TopSrcPort))
	rightLines = append(rightLines, fmt.Sprintf("  (%d vars)", len(flow.SrcPorts)))
	rightLines = append(rightLines, fmt.Sprintf("Dst Port: %d", flow.TopDstPort))
	rightLines = append(rightLines, fmt.Sprintf("  (%d vars)", len(flow.DstPorts)))
	rightLines = append(rightLines, "")

	// TCP State Changes section (if TCP)
	if flow.Protocol == "tcp" && len(flow.StateChanges) > 0 {
		rightLines = append(rightLines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("TCP States:"))
		for i, change := range flow.StateChanges {
			emoji := getStateEmoji(change.NewState)
			stateStyle := lipgloss.NewStyle().Foreground(getStateColor(change.NewState))
			
			var duration time.Duration
			if i < len(flow.StateChanges)-1 {
				duration = flow.StateChanges[i+1].Timestamp.Sub(change.Timestamp)
			} else {
				duration = time.Now().Sub(change.Timestamp)
			}
			
			line := fmt.Sprintf("%s %s", emoji, change.NewState)
			line = fmt.Sprintf("%s (%s)", line, formatDuration(duration))
			rightLines = append(rightLines, stateStyle.Render(line))
		}
		rightLines = append(rightLines, "")
	}

	// DNS section summary (if DNS queries)
	if len(flow.DNSQueries) > 0 {
		rightLines = append(rightLines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("DNS:"))
		rightLines = append(rightLines, fmt.Sprintf("Queries: %d", len(flow.DNSQueries)))
		
		// Show unique domains
		uniqueDomains := make(map[string]bool)
		for _, dq := range flow.DNSQueries {
			uniqueDomains[dq.Domain] = true
		}
		rightLines = append(rightLines, fmt.Sprintf("Domains: %d", len(uniqueDomains)))
		
		// Show first 3 domains
		count := 0
		for domain := range uniqueDomains {
			if count >= 3 {
				break
			}
			shortened := domain
			if len(shortened) > 18 {
				shortened = shortened[:15] + "..."
			}
			rightLines = append(rightLines, fmt.Sprintf("  • %s", shortened))
			count++
		}
	}

	// Pad right column to full height
	availableRows := d.height - 3
	for len(rightLines) < availableRows {
		rightLines = append(rightLines, "")
	}
	if len(rightLines) > availableRows {
		rightLines = rightLines[:availableRows]
	}

	// ===== LEFT COLUMN: Scrollable packet history =====
	leftLines := []string{}
	
	leftLines = append(leftLines, headerStyle.Render("PACKET HISTORY"))
	leftLines = append(leftLines, "─────────────────────────────────────────")
	leftLines = append(leftLines, "Time       │ Dir │ Src IP        │ Dst IP        │ Len")
	leftLines = append(leftLines, "───────────┼─────┼───────────────┼───────────────┼───")

	// Use cached packet history to avoid per-frame lock acquisitions
	historyLen := len(d.cachedPackets)
	if historyLen == 0 {
		leftLines = append(leftLines, "(no packets)")
	} else {
		// Use cached packets instead of calling GetAll() every frame
		for i := len(d.cachedPackets) - 1; i >= 0; i-- {
			pkt := d.cachedPackets[i]
			dirArrow := "→"
			if pkt.Direction == "reverse" {
				dirArrow = "←"
			}
			
			srcIP := pkt.SrcIP.String()
			dstIP := pkt.DstIP.String()
			if len(srcIP) > 13 {
				srcIP = srcIP[:10] + "..."
			}
			if len(dstIP) > 13 {
				dstIP = dstIP[:10] + "..."
			}
			
			line := fmt.Sprintf("%s │ %s │ %s │ %s │ %d",
				pkt.Timestamp.Format("15:04:05.00"),
				dirArrow,
				srcIP,
				dstIP,
				pkt.Length)
			leftLines = append(leftLines, line)
		}
	}

	// Apply scrolling to left column only
	maxScroll := len(leftLines) - availableRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if d.drillScroll > maxScroll {
		d.drillScroll = maxScroll
	}

	// Get visible lines for left column
	scrolledLeftLines := leftLines[d.drillScroll:]
	if len(scrolledLeftLines) > availableRows {
		scrolledLeftLines = scrolledLeftLines[:availableRows]
	}

	// Pad left column to match right column height
	for len(scrolledLeftLines) < availableRows {
		scrolledLeftLines = append(scrolledLeftLines, "")
	}

	// Create styled columns
	leftColStyle := lipgloss.NewStyle().
		Width(leftColWidth).
		Height(availableRows)
	
	rightColStyle := lipgloss.NewStyle().
		Width(rightColWidth).
		Height(availableRows).
		BorderLeft(true).
		BorderStyle(lipgloss.RoundedBorder()).
		Padding(0, 1)

	leftCol := leftColStyle.Render(lipgloss.JoinVertical(lipgloss.Left, scrolledLeftLines...))
	rightCol := rightColStyle.Render(lipgloss.JoinVertical(lipgloss.Left, rightLines...))

	// Combine columns
	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, leftCol, rightCol)

	// Add footer
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("[ESC/Q] Back | [↑↓/K/J] Scroll | [PgUp/PgDn] Jump")
	fullView := lipgloss.JoinVertical(lipgloss.Left, mainContent, "", footer)

	return fullView
}

// updateThroughputHistory updates the throughput tracking history
func (d *Dashboard) updateThroughputHistory() {
	if d.reader == nil {
		return
	}

	now := time.Now()
	timeDiff := now.Sub(d.lastStatsTime).Seconds()
	if timeDiff < 1.0 {
		return // Update once per second
	}

	kernelPkts, kernelBytes := d.reader.KernelStats()

	// Prevent massive spike on first tick
	if d.lastTotalPackets == 0 && kernelPkts > 0 {
		d.lastStatsTime = now
		d.lastTotalPackets = kernelPkts
		d.lastTotalBytes = kernelBytes
		return
	}

	packetsDiff := kernelPkts - d.lastTotalPackets
	bytesDiff := kernelBytes - d.lastTotalBytes

	pps := uint64(float64(packetsDiff) / timeDiff)
	bps := uint64(float64(bytesDiff) / timeDiff)

	sample := &ThroughputSample{
		Timestamp:     now,
		PacketsPerSec: pps,
		BytesPerSec:   bps,
	}

	d.throughputHistory = append(d.throughputHistory, sample)

	// Keep only last 60 samples
	if len(d.throughputHistory) > 60 {
		d.throughputHistory = d.throughputHistory[1:]
	}

	d.lastStatsTime = now
	d.lastTotalPackets = kernelPkts
	d.lastTotalBytes = kernelBytes
}

// renderRealTimeStats renders the real-time statistics widget
func (d *Dashboard) renderRealTimeStats() string {
	if d.globalStats == nil {
		return ""
	}

	width := (d.width / 2) - 6

	// Calculate current rates
	var pps, bps float64
	if len(d.throughputHistory) > 0 {
		latest := d.throughputHistory[len(d.throughputHistory)-1]
		pps = float64(latest.PacketsPerSec)
		bps = float64(latest.BytesPerSec)
	}

	mbps := bps / (1024 * 1024)

	// Find top protocol
	protoCount := make(map[string]uint64)
	for _, flow := range d.allFlows {
		protoCount[flow.Protocol] += flow.PacketCount
	}

	topProto := ""
	topProtoCount := uint64(0)
	for proto, count := range protoCount {
		if count > topProtoCount {
			topProtoCount = count
			topProto = proto
		}
	}

	lines := []string{
		fmt.Sprintf("┌─ REAL-TIME STATS %s┐", repeatStr("─", width-19)),
		fmt.Sprintf("│ Rate: %6.0f pps │ %6.2f Mbps │", pps, mbps),
		fmt.Sprintf("│ Top Proto: %-4s │ Flows: %3d │", topProto, len(d.allFlows)),
		fmt.Sprintf("└%s┘", repeatStr("─", width-2)),
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderProtocolDistribution renders the protocol distribution chart
func (d *Dashboard) renderProtocolDistribution() string {
	width := (d.width / 2) - 6

	// Count packets by protocol
	protoStats := make(map[string]uint64)
	totalPackets := uint64(0)
	for _, flow := range d.allFlows {
		protoStats[flow.Protocol] += flow.PacketCount
		totalPackets += flow.PacketCount
	}

	if totalPackets == 0 {
		return "┌─ PROTOCOL DISTRIBUTION ┐\n│ No data                  │\n└──────────────────────────┘"
	}

	// Sort protocols by count
	type protoData struct {
		name  string
		count uint64
	}
	protos := make([]protoData, 0, len(protoStats))
	for name, count := range protoStats {
		protos = append(protos, protoData{name, count})
	}
	sort.Slice(protos, func(i, j int) bool {
		return protos[i].count > protos[j].count
	})

	lines := []string{
		fmt.Sprintf("┌─ PROTOCOL DIST %s┐", repeatStr("─", width-17)),
	}

	for _, pd := range protos {
		pct := (float64(pd.count) / float64(totalPackets)) * 100
		barLen := int((pct / 100) * float64(width-22))
		if barLen < 1 {
			barLen = 1
		}
		bar := repeatStr("█", barLen) + repeatStr("░", (width-22)-barLen)
		lines = append(lines, fmt.Sprintf("│ %-4s %s %5.1f%% │", pd.name, bar, pct))
	}

	lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderTrafficSparkline renders the traffic throughput graph
func (d *Dashboard) renderTrafficSparkline() string {
	width := d.width - 4
	if width < 20 {
		width = 20
	}

	lines := []string{
		fmt.Sprintf("┌─ THROUGHPUT (Mbps) %s┐", repeatStr("─", width-23)),
	}

	if len(d.throughputHistory) == 0 {
		lines = append(lines, fmt.Sprintf("│ %s │", repeatStr(" ", width-2)))
		lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))
		return lipgloss.JoinVertical(lipgloss.Left, lines...)
	}

	// Find max throughput
	maxBps := uint64(0)
	for _, sample := range d.throughputHistory {
		if sample.BytesPerSec > maxBps {
			maxBps = sample.BytesPerSec
		}
	}

	if maxBps == 0 {
		maxBps = 1
	}

	// Create sparkline - show the most recent samples
	sparkChars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	availableWidth := width - 4
	
	// Take up to availableWidth most recent samples
	startIdx := 0
	if len(d.throughputHistory) > availableWidth {
		startIdx = len(d.throughputHistory) - availableWidth
	}
	
	sparkline := ""
	for i := startIdx; i < len(d.throughputHistory); i++ {
		sample := d.throughputHistory[i]
		ratio := float64(sample.BytesPerSec) / float64(maxBps)
		idx := int(ratio * 7)
		if idx > 7 {
			idx = 7
		}
		sparkline += string(sparkChars[idx])
	}

	// Pad sparkline on the right if not enough data yet
	if len(sparkline) < availableWidth {
		sparkline += repeatStr(" ", availableWidth-len(sparkline))
	}

	maxMbps := float64(maxBps) / (1024 * 1024)
	lines = append(lines, fmt.Sprintf("│ %s │", sparkline))
	lines = append(lines, fmt.Sprintf("│ Peak: %8.1f Mbps %s │", maxMbps, repeatStr(" ", width-24)))
	lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderTopTalkers renders the top talkers widget
func (d *Dashboard) renderTopTalkers() string {
	width := (d.width / 2) - 6

	lines := []string{
		fmt.Sprintf("┌─ TOP TALKERS %s┐", repeatStr("─", width-14)),
	}

	// Sort flows by bytes
	sorted := make([]*model.Flow, len(d.allFlows))
	copy(sorted, d.allFlows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ByteCount > sorted[j].ByteCount
	})

	// Show top 5
	count := 5
	if len(sorted) < 5 {
		count = len(sorted)
	}

	if count == 0 {
		lines = append(lines, "│ No flows                 │")
	} else {
		for i := 0; i < count; i++ {
			flow := sorted[i]
			label := fmt.Sprintf("%s→%s", shortIP(flow.SrcIP), shortIP(flow.DstIP))
			bytes := formatBytes(flow.ByteCount)
			line := fmt.Sprintf("│ %d. %-10s %8s │", i+1, label, bytes)
			lines = append(lines, line[:min(len(line), width+2)])
		}
	}

	lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderPortAnalyzer renders the port analyzer widget
func (d *Dashboard) renderPortAnalyzer() string {
	width := (d.width / 2) - 6

	lines := []string{
		fmt.Sprintf("┌─ TOP PORTS %s┐", repeatStr("─", width-13)),
	}

	// Count port usage
	portCount := make(map[uint16]uint64)
	for _, flow := range d.allFlows {
		portCount[flow.TopDstPort] += flow.PacketCount
	}

	// Sort ports
	type portData struct {
		port  uint16
		count uint64
	}
	ports := make([]portData, 0, len(portCount))
	for port, count := range portCount {
		if port > 0 {
			ports = append(ports, portData{port, count})
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].count > ports[j].count
	})

	// Show top 5 ports
	count := 5
	if len(ports) < 5 {
		count = len(ports)
	}

	if count == 0 {
		lines = append(lines, "│ No ports                 │")
	} else {
		for i := 0; i < count; i++ {
			portData := ports[i]
			serviceName := getServiceName(portData.port)
			line := fmt.Sprintf("│ %d. Port %-5d %-8s │", i+1, portData.port, serviceName)
			lines = append(lines, line[:min(len(line), width+2)])
		}
	}

	lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderHelp renders the help dialog
func (d *Dashboard) renderHelp() string {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39"))
	
	title := headerStyle.Render("═════════════════════════════════════════════════════════════════")
	subtitle := headerStyle.Render("KEYBOARD SHORTCUTS")
	underline := headerStyle.Render("═════════════════════════════════════════════════════════════════")

	helpLines := []string{title, "", subtitle, underline, ""}

	helpLines = append(helpLines, "Navigation:")
	helpLines = append(helpLines, "  [↑] or [K]           Move up in flow table")
	helpLines = append(helpLines, "  [↓] or [J]           Move down in flow table")
	helpLines = append(helpLines, "  [Page Up]            Scroll main view up (10 lines)")
	helpLines = append(helpLines, "  [Page Down]          Scroll main view down (10 lines)")
	helpLines = append(helpLines, "  [Mouse Wheel]        Scroll main view (3 lines per tick)")
	helpLines = append(helpLines, "  ")
	helpLines = append(helpLines, "Flow View:")
	helpLines = append(helpLines, "  [Enter]              Drill into selected flow for details")
	helpLines = append(helpLines, "  [P]                  Pause/resume packet capture")
	helpLines = append(helpLines, "  [S]                  Cycle sort order (bytes/packets/duration)")
	helpLines = append(helpLines, "  [F]                  Filter by protocol")
	helpLines = append(helpLines, "  ")
	helpLines = append(helpLines, "Drill-Down View:")
	helpLines = append(helpLines, "  [↑] or [K]           Scroll up in packet history")
	helpLines = append(helpLines, "  [↓] or [J]           Scroll down in packet history")
	helpLines = append(helpLines, "  [Page Up/Down]       Scroll 10 lines")
	helpLines = append(helpLines, "  [Mouse Wheel]        Scroll (3 lines per tick)")
	helpLines = append(helpLines, "  [ESC] or [Q]         Exit drill-down and return to main view")
	helpLines = append(helpLines, "  ")
	helpLines = append(helpLines, "General:")
	helpLines = append(helpLines, "  [?]                  Show this help")
	helpLines = append(helpLines, "  [Q]                  Quit JOPIL")
	helpLines = append(helpLines, "")
	helpLines = append(helpLines, "  Press [ESC] or [Q] to close this help")

	return lipgloss.JoinVertical(lipgloss.Left, helpLines...)
}

// renderFilterDialog renders the filter selection dialog
func (d *Dashboard) renderFilterDialog() string {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39"))
	
	title := headerStyle.Render("═════════════════════════════════════════════════════════════════")
	subtitle := headerStyle.Render("SELECT PROTOCOL FILTER")
	underline := headerStyle.Render("═════════════════════════════════════════════════════════════════")

	filterLines := []string{title, "", subtitle, underline, ""}

	// Display protocol options
	for _, proto := range d.availableProtos {
		prefix := "  "
		if proto == d.filterInput {
			prefix = "▶ "
		}
		
		label := proto
		if proto == "" {
			label = "(none - show all)"
		}
		
		filterLines = append(filterLines, fmt.Sprintf("%s%s", prefix, label))
	}

	filterLines = append(filterLines, "")
	filterLines = append(filterLines, "  [ENTER] Apply  │  [ESC] Cancel  │  [↑↓] Navigate")

	return lipgloss.JoinVertical(lipgloss.Left, filterLines...)
}

// handleKeypress processes keyboard input
func (d *Dashboard) handleKeypress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// If in help mode, handle help-specific keys
	if d.helpMode {
		switch msg.String() {
		case "esc", "q", "?":
			d.helpMode = false
			return d, nil
		}
		return d, nil
	}

	// If in filter mode, handle filter-specific keys
	if d.filterMode {
		switch msg.String() {
		case "esc":
			d.filterMode = false
			d.filterInput = ""
			return d, nil
		case "enter":
			// Apply the filter
			d.filterProto = d.filterInput
			d.applyFilters()
			// Sort the newly filtered results
			d.sortFlows()
			d.filterMode = false
			d.filterInput = ""
			// Reset selection to top after filter
			d.selectedFlow = 0
			d.selectedFlowId = ""
			return d, nil
		case "up":
			// Cycle through available protocols backwards
			for i := len(d.availableProtos) - 1; i >= 0; i-- {
				if d.availableProtos[i] == d.filterInput {
					if i > 0 {
						d.filterInput = d.availableProtos[i-1]
					} else {
						d.filterInput = d.availableProtos[len(d.availableProtos)-1]
					}
					break
				}
			}
		case "down":
			// Cycle through available protocols
			for i := 0; i < len(d.availableProtos); i++ {
				if d.availableProtos[i] == d.filterInput {
					if i < len(d.availableProtos)-1 {
						d.filterInput = d.availableProtos[i+1]
					} else {
						d.filterInput = d.availableProtos[0]
					}
					break
				}
			}
		}
		return d, nil
	}

	// If in drill mode, handle drill-specific keys
	if d.drillMode {
		switch msg.String() {
		case "esc", "q":
			d.drillMode = false
			d.drillScroll = 0
			d.frozenFlows = nil
			d.cachedPackets = nil  // Clear cache when exiting drill mode
			return d, nil
		case "up", "k":
			if d.drillScroll > 0 {
				d.drillScroll--
			}
		case "down", "j":
			// Calculate the actual max scroll for bounds checking
			if d.drillFlowIdx < len(d.frozenFlows) {
				flow := d.frozenFlows[d.drillFlowIdx]
				
				// Estimate content lines (similar to renderDrillDown)
				contentLines := 50 + flow.PacketHistory.Len() + len(flow.StateChanges) + len(flow.DNSQueries)
				availableRows := d.height - 2
				if availableRows < 10 {
					availableRows = 10
				}
				
				maxScroll := contentLines - availableRows
				if maxScroll < 0 {
					maxScroll = 0
				}
				
				if d.drillScroll < maxScroll {
					d.drillScroll++
				}
			}
		case "pgup":
			// Scroll up 10 lines in drill view
			d.drillScroll -= 10
			if d.drillScroll < 0 {
				d.drillScroll = 0
			}
		case "pgdn":
			// Scroll down 10 lines in drill view with bounds
			if d.drillFlowIdx < len(d.frozenFlows) {
				flow := d.frozenFlows[d.drillFlowIdx]
				contentLines := 50 + flow.PacketHistory.Len() + len(flow.StateChanges) + len(flow.DNSQueries)
				availableRows := d.height - 2
				if availableRows < 10 {
					availableRows = 10
				}
				maxScroll := contentLines - availableRows
				if maxScroll < 0 {
					maxScroll = 0
				}
				d.drillScroll += 10
				if d.drillScroll > maxScroll {
					d.drillScroll = maxScroll
				}
			}
		}
		return d, nil
	}

	// Main view keyboard handling
	switch msg.String() {
	case "q", "ctrl+c":
		return d, tea.Quit
	case "p":
		d.paused = !d.paused
	case "up", "k":
		if d.selectedFlow > 0 {
			d.selectedFlow--
			if d.selectedFlow < d.tableScroll {
				d.tableScroll = d.selectedFlow
			}
			// Update selectedFlowId to track new selection
			if d.selectedFlow < len(d.flows) {
				d.selectedFlowId = d.getFlowId(d.flows[d.selectedFlow])
			}
		}
	case "down", "j":
		if d.selectedFlow < len(d.flows)-1 {
			d.selectedFlow++
			availableRows := d.height - 12
			if availableRows < 3 {
				availableRows = 3
			}
			if d.selectedFlow >= d.tableScroll+availableRows {
				d.tableScroll = d.selectedFlow - availableRows + 1
			}
			// Update selectedFlowId to track new selection
			if d.selectedFlow < len(d.flows) {
				d.selectedFlowId = d.getFlowId(d.flows[d.selectedFlow])
			}
		}
	case "enter":
		// Enter drill-down mode
		if d.selectedFlow < len(d.flows) {
			d.drillMode = true
			d.drillFlowIdx = d.selectedFlow
			d.drillScroll = 0
			// Freeze flows snapshot when entering drill-down
			d.frozenFlows = make([]*model.Flow, len(d.flows))
			copy(d.frozenFlows, d.flows)
			
			// Cache packet history once to avoid per-frame lock acquisitions
			if d.drillFlowIdx < len(d.frozenFlows) {
				flow := d.frozenFlows[d.drillFlowIdx]
				d.cachedPackets = flow.PacketHistory.GetAll()  // Lock once, cache result
			}
		}
	case "f":
		// Enter filter mode
		d.filterMode = true
		d.filterInput = d.filterProto
	case "s":
		// Cycle sort order and resort flows
		switch d.sortBy {
		case "bytes":
			d.sortBy = "packets"
		case "packets":
			d.sortBy = "duration"
		case "duration":
			d.sortBy = "latest"
		default:
			d.sortBy = "bytes"
		}
		// Re-sort flows with new sort order
		d.sortFlows()
		// Reset to top of sorted list
		d.selectedFlow = 0
		d.tableScroll = 0
		d.selectedFlowId = ""
	case "pgup":
		// Scroll main view up by half page (10 lines)
		d.mainScroll -= 10
		if d.mainScroll < 0 {
			d.mainScroll = 0
		}
	case "pgdn":
		// Scroll main view down by half page (10 lines)
		d.mainScroll += 10
	case "?":
		d.helpMode = true
	}

	return d, nil
}

// handleMouseScroll handles mouse wheel events for scrolling
func (d *Dashboard) handleMouseScroll(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	// Handle scrolling in drill-down view
	if d.drillMode && d.drillFlowIdx < len(d.frozenFlows) {
		flow := d.frozenFlows[d.drillFlowIdx]
		contentLines := 50 + flow.PacketHistory.Len() + len(flow.StateChanges) + len(flow.DNSQueries)
		availableRows := d.height - 2
		if availableRows < 10 {
			availableRows = 10
		}
		maxScroll := contentLines - availableRows
		if maxScroll < 0 {
			maxScroll = 0
		}

		switch msg.Type {
		case tea.MouseWheelUp:
			d.drillScroll -= 3
			if d.drillScroll < 0 {
				d.drillScroll = 0
			}
		case tea.MouseWheelDown:
			d.drillScroll += 3
			if d.drillScroll > maxScroll {
				d.drillScroll = maxScroll
			}
		}
		return d, nil
	}

	// Handle scrolling in main view
	if d.helpMode || d.filterMode {
		return d, nil
	}

	switch msg.Type {
	case tea.MouseWheelUp:
		// Scroll up (3 lines per wheel tick)
		d.mainScroll -= 3
		if d.mainScroll < 0 {
			d.mainScroll = 0
		}
	case tea.MouseWheelDown:
		// Scroll down (3 lines per wheel tick)
		d.mainScroll += 3
	}

	return d, nil
}

// sortFlows sorts the flows based on current sort criteria
func (d *Dashboard) sortFlows() {
	sort.Slice(d.flows, func(i, j int) bool {
		switch d.sortBy {
		case "latest":
			return d.flows[i].LastPacketTime.After(d.flows[j].LastPacketTime)
		case "packets":
			return d.flows[i].PacketCount > d.flows[j].PacketCount
		case "duration":
			durationI := d.flows[i].LastPacketTime.Sub(d.flows[i].FirstPacketTime)
			durationJ := d.flows[j].LastPacketTime.Sub(d.flows[j].FirstPacketTime)
			return durationI > durationJ
		default: // bytes
			return d.flows[i].ByteCount > d.flows[j].ByteCount
		}
	})
}

// applyFilters filters flows based on current filter criteria
func (d *Dashboard) applyFilters() {
	if d.filterProto == "" {
		// No filter, show all flows
		d.flows = d.allFlows
	} else {
		filtered := make([]*model.Flow, 0)
		for _, flow := range d.allFlows {
			if flow.Protocol == d.filterProto {
				filtered = append(filtered, flow)
			}
		}
		d.flows = filtered
	}
	// NOTE: Do NOT sort here - only filter!
	// Sorting happens explicitly when user presses 'S' or applies a new filter
}

// getFlowId returns a unique identifier for a flow
func (d *Dashboard) getFlowId(flow *model.Flow) string {
	return fmt.Sprintf("%s|%s|%s", flow.SrcIP.String(), flow.DstIP.String(), flow.Protocol)
}

// updateFlows updates the flows list from the aggregator
func (d *Dashboard) updateFlows() {
	if d.paused {
		return
	}

	newFlows := d.aggregator.GetAllFlows()

	// Build lookup map of what aggregator currently has
	newFlowMap := make(map[string]*model.Flow, len(newFlows))
	for _, flow := range newFlows {
		newFlowMap[d.getFlowId(flow)] = flow
	}

	// Update existing flows and REMOVE ones that disappeared
	kept := d.flows[:0] // reuse slice backing array
	for _, currentFlow := range d.flows {
		flowId := d.getFlowId(currentFlow)
		if newFlow, exists := newFlowMap[flowId]; exists {
			// Update stats in-place
			currentFlow.ByteCount = newFlow.ByteCount
			currentFlow.PacketCount = newFlow.PacketCount
			currentFlow.ForwardBytes = newFlow.ForwardBytes
			currentFlow.ReverseBytes = newFlow.ReverseBytes
			currentFlow.ForwardPackets = newFlow.ForwardPackets
			currentFlow.ReversePackets = newFlow.ReversePackets
			currentFlow.LastPacketTime = newFlow.LastPacketTime
			currentFlow.DNSQueries = newFlow.DNSQueries
			currentFlow.DNSQueryNames = newFlow.DNSQueryNames
			currentFlow.DNSFailures = newFlow.DNSFailures
			currentFlow.DNSLastQuery = newFlow.DNSLastQuery
			currentFlow.PacketHistory = newFlow.PacketHistory
			kept = append(kept, currentFlow)
		}
		// flows missing from newFlowMap are simply dropped (timed out)
	}
	d.flows = kept

	// Add brand new flows
	existingMap := make(map[string]bool, len(d.flows))
	for _, flow := range d.flows {
		existingMap[d.getFlowId(flow)] = true
	}
	
	newFlowsAdded := 0
	for _, newFlow := range newFlows {
		if !existingMap[d.getFlowId(newFlow)] {
			d.flows = append(d.flows, newFlow)
			newFlowsAdded++
		}
	}

	// Sort and track selection
	if len(d.flows) > 0 {
		d.sortFlows()
		if d.selectedFlowId != "" {
			for i, flow := range d.flows {
				if d.getFlowId(flow) == d.selectedFlowId {
					d.selectedFlow = i
					break
				}
			}
		}
	}

	d.allFlows = newFlows
	d.lastUpdate = time.Now()
}

// updateStats updates the global statistics
func (d *Dashboard) updateStats() {
	d.globalStats = d.aggregator.GetGlobalStats()
}

// refreshFlows sends a command to refresh flows
func (d *Dashboard) refreshFlows() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return RefreshFlowsMsg{Time: t}
	})
}

// RefreshFlowsMsg is triggered to refresh flows
type RefreshFlowsMsg struct {
	Time time.Time
}

// renderStatusLog renders a status log widget showing recent system messages
func (d *Dashboard) renderStatusLog() string {
	width := d.width - 4
	if width < 30 {
		width = 30
	}

	lines := []string{
		fmt.Sprintf("┌─ STATUS LOG %s┐", repeatStr("─", width-14)),
	}

	if d.reader != nil && d.reader.Status != nil {
		msgs := d.reader.Status.GetRecent(4)
		if len(msgs) == 0 {
			lines = append(lines, fmt.Sprintf("│ (no messages) %s│", repeatStr(" ", width-17)))
		} else {
			for _, msg := range msgs {
				timeStr := msg.Time.Format("15:04:05")
				icon := "·"
				switch msg.Level {
				case "warn":
					icon = "⚠"
				case "error":
					icon = "✘"
				case "info":
					icon = "✓"
				}
				
				msgText := msg.Message
				maxMsgLen := width - 15
				if maxMsgLen < 10 {
					maxMsgLen = 10
				}
				if len(msgText) > maxMsgLen {
					msgText = msgText[:maxMsgLen-3] + "..."
				}
				
				line := fmt.Sprintf("│ %s %s %s", icon, timeStr, msgText)
				// Pad to width
				if len(line) < width {
					line += repeatStr(" ", width-len(line)) + "│"
				} else {
					line = line[:width-1] + "│"
				}
				lines = append(lines, line)
			}
		}
	} else {
		lines = append(lines, fmt.Sprintf("│ (no reader) %s│", repeatStr(" ", width-15)))
	}

	lines = append(lines, fmt.Sprintf("└%s┘", repeatStr("─", width-2)))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// Helper functions

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// repeatStr repeats a string N times
func repeatStr(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// shortIP returns the last octet of an IP for display
func shortIP(ip net.IP) string {
	if ip == nil {
		return "?"
	}
	parts := ip.String()
	// Extract last octet
	lastDot := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '.' {
			lastDot = i
			break
		}
	}
	if lastDot >= 0 {
		return parts[lastDot+1:]
	}
	return parts
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getServiceName returns the common service name for a port
func getServiceName(port uint16) string {
	switch port {
	case 20:
		return "FTP-DATA"
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 67:
		return "DHCP"
	case 68:
		return "DHCP"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 123:
		return "NTP"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PG"
	case 5900:
		return "VNC"
	case 8080:
		return "HTTP-8080"
	case 27017:
		return "MongoDB"
	default:
		return ""
	}
}

