package sniffer

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// Flow represents a network flow between a source and destination.
type Flow struct {
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     int       `json:"src_port"`
	DstPort     int       `json:"dst_port"`
	Protocol    int       `json:"protocol"` // 1=TCP, 2=UDP, 3=ICMP
	StartTime   time.Time `json:"start_time"`
	LastSeen    time.Time `json:"last_seen"`
	PacketCount int       `json:"packet_count"`
	ByteCount   int       `json:"byte_count"`
	FlagSYN     int       `json:"flag_syn"`
	FlagACK     int       `json:"flag_ack"`
	FlagFIN     int       `json:"flag_fin"`
	Classified  int       `json:"classified"`       // 0=Benign, 1=DDoS, 2=PortScan, 3=BruteForce
	Status      string    `json:"status"`           // "BENIGN", "DDOS", "PORTSCAN", "BRUTEFORCE"
	Active      bool      `json:"active"`
}

// PacketMetadata holds parsed packet info passed to the flow tracker.
type PacketMetadata struct {
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  int // 1=TCP, 2=UDP, 3=ICMP
	Length    int
	IsSYN     bool
	IsACK     bool
	IsFIN     bool
	Timestamp time.Time
}

// FlowTracker manages concurrent active network flows.
type FlowTracker struct {
	flows      map[string]*Flow
	mu         sync.RWMutex
	Broadcast  chan *Flow
	AlertChan  chan *Flow
	Inference  func([]float64) int
}

func NewFlowTracker(inferenceFn func([]float64) int) *FlowTracker {
	return &FlowTracker{
		flows:      make(map[string]*Flow),
		Broadcast:  make(chan *Flow, 100),
		AlertChan:  make(chan *Flow, 100),
		Inference:  inferenceFn,
	}
}

// ProcessPacket updates flow statistics with packet metadata.
func (ft *FlowTracker) ProcessPacket(p PacketMetadata) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	// 5-tuple key: srcIP:srcPort -> dstIP:dstPort [protocol]
	key := fmt.Sprintf("%s:%d->%s:%d[%d]", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Protocol)

	flow, exists := ft.flows[key]
	if !exists {
		flow = &Flow{
			SrcIP:       p.SrcIP,
			DstIP:       p.DstIP,
			SrcPort:     p.SrcPort,
			DstPort:     p.DstPort,
			Protocol:    p.Protocol,
			StartTime:   p.Timestamp,
			LastSeen:    p.Timestamp,
			PacketCount: 0,
			ByteCount:   0,
			FlagSYN:     0,
			FlagACK:     0,
			FlagFIN:     0,
			Active:      true,
		}
		ft.flows[key] = flow
	}

	flow.LastSeen = p.Timestamp
	flow.PacketCount++
	flow.ByteCount += p.Length
	if p.IsSYN {
		flow.FlagSYN++
	}
	if p.IsACK {
		flow.FlagACK++
	}
	if p.IsFIN {
		flow.FlagFIN++
	}
}

// RunCleaner periodically reviews flows, runs ML inference, and cleans inactive flows.
func (ft *FlowTracker) RunCleaner(interval time.Duration, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		ft.mu.Lock()
		now := time.Now()
		for key, flow := range ft.flows {
			duration := flow.LastSeen.Sub(flow.StartTime).Seconds()
			if duration <= 0 {
				duration = 0.001
			}

			// Prepare features for inference
			features := []float64{
				duration,
				float64(flow.Protocol),
				float64(flow.PacketCount),
				float64(flow.ByteCount),
				float64(flow.SrcPort),
				float64(flow.DstPort),
				float64(flow.FlagSYN),
				float64(flow.FlagACK),
				float64(flow.FlagFIN),
			}

			// Run classifier
			flow.Classified = ft.Inference(features)
			flow.Status = GetStatusString(flow.Classified)

			// If dynamic threat is detected or flow is timed out, report/clean
			timeSinceLastSeen := now.Sub(flow.LastSeen)

			// Broadcast active stats
			select {
			case ft.Broadcast <- flow:
			default:
			}

			if flow.Classified != 0 {
				select {
				case ft.AlertChan <- flow:
				default:
				}
			}

			if timeSinceLastSeen > timeout {
				flow.Active = false
				delete(ft.flows, key)
			}
		}
		ft.mu.Unlock()
	}
}

func GetStatusString(class int) string {
	switch class {
	case 0:
		return "BENIGN"
	case 1:
		return "DDOS"
	case 2:
		return "PORTSCAN"
	case 3:
		return "BRUTEFORCE"
	default:
		return "UNKNOWN"
	}
}

// StartMockGenerator generates synthetic network activity to power the UI immediately.
func (ft *FlowTracker) StartMockGenerator() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Normal traffic loop
	go func() {
		for {
			time.Sleep(time.Duration(r.Intn(500)+100) * time.Millisecond)
			
			// Benign HTTP/HTTPS request
			dstPort := 80
			if r.Float64() > 0.5 {
				dstPort = 443
			}
			
			ft.ProcessPacket(PacketMetadata{
				SrcIP:     fmt.Sprintf("192.168.1.%d", r.Intn(50)+10),
				DstIP:     "10.0.0.5",
				SrcPort:   r.Intn(64000) + 1024,
				DstPort:   dstPort,
				Protocol:  1, // TCP
				Length:    r.Intn(1000) + 64,
				IsSYN:     r.Float64() > 0.9,
				IsACK:     true,
				IsFIN:     r.Float64() > 0.95,
				Timestamp: time.Now(),
			})
		}
	}()

	// Periodic Attack Trigger loop
	go func() {
		for {
			// Wait between 15 to 30 seconds to launch an attack
			time.Sleep(time.Duration(r.Intn(15)+15) * time.Second)
			
			attackType := r.Intn(3) + 1 // 1=DDoS, 2=PortScan, 3=BruteForce
			srcIP := fmt.Sprintf("185.220.101.%d", r.Intn(254)+1)
			
			switch attackType {
			case 1: // DDoS
				fmt.Println("[Mock Attack] Launching DDoS Syn Flood Simulation...")
				for i := 0; i < 200; i++ {
					ft.ProcessPacket(PacketMetadata{
						SrcIP:     srcIP,
						DstIP:     "10.0.0.5",
						SrcPort:   r.Intn(64000) + 1024,
						DstPort:   80,
						Protocol:  1,
						Length:    64,
						IsSYN:     true,
						IsACK:     false,
						IsFIN:     false,
						Timestamp: time.Now(),
					})
					time.Sleep(2 * time.Millisecond) // high speed
				}
				
			case 2: // Port Scan
				fmt.Println("[Mock Attack] Launching TCP Port Scan Simulation...")
				for port := 20; port < 120; port++ {
					ft.ProcessPacket(PacketMetadata{
						SrcIP:     srcIP,
						DstIP:     "10.0.0.5",
						SrcPort:   r.Intn(64000) + 1024,
						DstPort:   port,
						Protocol:  1,
						Length:    40,
						IsSYN:     true,
						IsACK:     false,
						IsFIN:     false,
						Timestamp: time.Now(),
					})
					time.Sleep(10 * time.Millisecond)
				}
				
			case 3: // Brute Force
				fmt.Println("[Mock Attack] Launching SSH Brute Force Simulation...")
				dstPort := 22 // SSH
				if r.Float64() > 0.5 {
					dstPort = 21 // FTP
				}
				
				for i := 0; i < 15; i++ {
					// Simulate connection attempt
					timestamp := time.Now()
					// Connection start
					ft.ProcessPacket(PacketMetadata{
						SrcIP:     srcIP,
						DstIP:     "10.0.0.5",
						SrcPort:   r.Intn(64000) + 1024,
						DstPort:   dstPort,
						Protocol:  1,
						Length:    120,
						IsSYN:     true,
						IsACK:     true,
						IsFIN:     false,
						Timestamp: timestamp,
					})
					time.Sleep(150 * time.Millisecond)
				}
			}
		}
	}()
}
