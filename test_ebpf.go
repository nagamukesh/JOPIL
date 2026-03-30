package main

import (
	"fmt"
	"log"
	"time"

	"github.com/mukesh/jopil/internal/monitor"
)

func main() {
	er, err := monitor.NewEventReader("", true)
	if err != nil {
		log.Fatalf("failed: %v", err)
	}
	defer er.Close()

	er.Start()

	timeout := time.After(10 * time.Second)
	for i := 0; i < 5; i++ {
		select {
		case evt := <-er.Events():
			fmt.Printf("Got event: %+v\n", evt)
		case <-timeout:
			fmt.Println("Timed out waiting for events. Debug packet count:", er.DebugPacketCount())
			// Let's print the status log
			for _, msg := range er.Status.GetRecent(10) {
				fmt.Printf("STATUS %s: %s\n", msg.Level, msg.Message)
			}
			return
		}
	}
}
