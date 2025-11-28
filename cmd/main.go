package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"JOPIL-Golang/internal/api"
	"JOPIL-Golang/internal/monitor"
)

func main() {
	server := api.NewServer()
	mon := monitor.New("wlo1", server.EventsChan)

	log.Println("Starting Packet Visualizer...")

	if err := mon.Start(); err != nil {
		log.Fatalf("Error starting BPF monitor: %v", err)
	}
	defer mon.Close()

	go server.Start()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Shutting down...")
}
