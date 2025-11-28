package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"JOPIL-Golang/internal/model"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Server struct {
	clients       map[*websocket.Conn]bool
	broadcast     chan map[string]interface{}
	EventsChan    chan model.PacketEvent
	mutex         sync.Mutex
	totalPackets  int64
	totalBytes    int64
	startTime     time.Time
	flows         map[string]*FlowStats
	protocolStats map[string]int64
	cpuStats      map[uint32]int64
}

type FlowStats struct {
	FlowID      string
	Protocol    string
	PacketCount int64
	TotalBytes  uint64
	TotalLatency float64
	ProbeCount  int64
	Hash        string
}

func NewServer() *Server {
	return &Server{
		clients:       make(map[*websocket.Conn]bool),
		broadcast:     make(chan map[string]interface{}, 1024),
		EventsChan:    make(chan model.PacketEvent, 1024),
		startTime:     time.Now(),
		flows:         make(map[string]*FlowStats),
		protocolStats: make(map[string]int64),
		cpuStats:      make(map[uint32]int64),
	}
}

func (s *Server) Start() {
	go s.processEvents()
	go s.handleBroadcast()

	http.HandleFunc("/ws", s.handleConnections)
	http.HandleFunc("/api/stats", s.handleStatsAPI)
	http.HandleFunc("/api/flows", s.handleFlowsAPI)
	http.Handle("/", http.FileServer(http.Dir("./web/templates")))

	log.Println("Web server listening on :5000")
	if err := http.ListenAndServe(":5000", nil); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) processEvents() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var packetCount int

	for {
		select {
		case event := <-s.EventsChan:
			packetCount++
			s.totalPackets++
			s.totalBytes += int64(event.Len)

			jsonEvent := event.ToJSON()
			flowID := fmt.Sprintf("%s:%d -> %s:%d", jsonEvent["src_ip"], jsonEvent["src_port"], jsonEvent["dst_ip"], jsonEvent["dst_port"])
			flowKey := fmt.Sprintf("%s_%s", jsonEvent["hash"], jsonEvent["protocol"])

			if flow, exists := s.flows[flowKey]; exists {
				flow.PacketCount++
				flow.TotalBytes += uint64(event.Len)
				flow.ProbeCount++
			} else {
				s.flows[flowKey] = &FlowStats{
					FlowID:      flowID,
					Protocol:    jsonEvent["protocol"].(string),
					PacketCount: 1,
					TotalBytes:  uint64(event.Len),
					Hash:        jsonEvent["hash"].(string),
				}
			}

			proto := jsonEvent["protocol"].(string)
			s.protocolStats[proto]++
			s.cpuStats[event.CpuID]++

			jsonEvent["flow_id"] = flowID
			s.broadcast <- map[string]interface{}{
				"type": "new_packet",
				"data": jsonEvent,
			}

		case <-ticker.C:
			s.broadcast <- map[string]interface{}{
				"type": "timeseries_update",
				"data": map[string]interface{}{
					"current_rate": packetCount,
					"current_pps":  packetCount,
					"timestamps":   []int{0},
					"packet_rate":  []int{packetCount},
					"avg_latency":  []float64{0},
				},
			}
			packetCount = 0
		}
	}
}

func (s *Server) handleBroadcast() {
	for msg := range s.broadcast {
		s.mutex.Lock()
		for client := range s.clients {
			err := client.WriteJSON(msg)
			if err != nil {
				client.Close()
				delete(s.clients, client)
			}
		}
		s.mutex.Unlock()
	}
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.mutex.Lock()
	s.clients[ws] = true
	s.mutex.Unlock()

	stats := s.getStats()
	ws.WriteJSON(map[string]interface{}{
		"type": "initial_stats",
		"data": stats,
	})
}

func (s *Server) getStats() map[string]interface{} {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	uptime := time.Since(s.startTime).Seconds()

	protoMap := make(map[string]interface{})
	for proto, count := range s.protocolStats {
		protoMap[proto] = count
	}

	cpuMap := make(map[string]interface{})
	for cpu, count := range s.cpuStats {
		cpuMap[fmt.Sprintf("%d", cpu)] = count
	}

	return map[string]interface{}{
		"total_packets": s.totalPackets,
		"total_bytes":   s.totalBytes,
		"flow_count":    len(s.flows),
		"uptime":        uptime,
		"protocols":     protoMap,
		"cpus":          cpuMap,
	}
}

func (s *Server) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := s.getStats()
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleFlowsAPI(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	flows := make([]map[string]interface{}, 0)

	for _, flow := range s.flows {
		flows = append(flows, map[string]interface{}{
			"hash":         flow.Hash,
			"flow_id":      flow.FlowID,
			"protocol":     flow.Protocol,
			"packet_count": flow.PacketCount,
			"total_bytes":  flow.TotalBytes,
			"total_latency": flow.TotalLatency,
			"probe_count":  flow.ProbeCount,
		})
	}

	json.NewEncoder(w).Encode(flows)
}