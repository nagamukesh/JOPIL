package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mukesh/jopil/internal/monitor"
	"github.com/mukesh/jopil/internal/tui"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Print("\033[?1003l\033[?1000l")
			fmt.Print("\033[?1049l")
			fmt.Printf("\nFATAL CRASH: %v\n", r)
			os.Exit(1)
		}
	}()

	// CLI flags
	ifaceName := flag.String("iface", "", "Network interface to attach XDP to (default: auto-detect)")
	flowTimeout := flag.Duration("timeout", 5*time.Minute, "Flow timeout duration")
	logFile := flag.String("log", "", "Log file path (empty = stderr)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	packetBuffer := flag.Int("packet-buffer", 5000, "Packet history buffer size per flow (1000-50000)")
	help := flag.Bool("help", false, "Show help")
	version := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Println("jopil v0.2.0")
		os.Exit(0)
	}

	// Setup logging
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Could not open log file: %v", err)
		}
		log.SetOutput(f)
	}
	log.SetFlags(log.Ltime | log.Lshortfile)

	// Must be root for XDP
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "ERROR: JOPIL requires root privileges for XDP eBPF.\nUsage: sudo ./jopil\n")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[Main] Starting JOPIL — Journey of Packets in Linux Kernel")

	// Initialize XDP eBPF reader
	reader, err := monitor.NewEventReader(*ifaceName, *verbose)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize XDP: %v\n", err)
	}
	defer reader.Close()

	reader.Start()

	// Clamp packet buffer
	if *packetBuffer < 1000 {
		*packetBuffer = 1000
	}
	if *packetBuffer > 50000 {
		*packetBuffer = 50000
	}

	// Create flow aggregator
	aggregator := monitor.NewFlowAggregator(reader.Events(), *flowTimeout, *packetBuffer)
	aggregator.Start(ctx)

	// Start TUI
	dashboard := tui.NewDashboard(aggregator, reader)
	p := tea.NewProgram(dashboard, tea.WithAltScreen(), tea.WithMouseCellMotion())

	go func() {
		<-sigChan
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		log.Printf("[Main] TUI Error: %v\n", err)
	}

	aggregator.Stop()
	log.Println("[Main] JOPIL shut down cleanly")
}
