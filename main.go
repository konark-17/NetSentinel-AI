package main

import (
	"log"
	"path/filepath"
	"time"

	"netsentinel/pkg/classifier"
	"netsentinel/pkg/server"
	"netsentinel/pkg/sniffer"
)

func main() {
	log.Println("Initializing NetSentinel AI...")

	// 1. Initialize FlowTracker with Python-trained classifier model
	tracker := sniffer.NewFlowTracker(classifier.Predict)

	// 2. Start Cleaner loop (checks flow rates, runs ML, trims inactive flows)
	// Check every 1 second, expire flows after 10 seconds of silence
	go tracker.RunCleaner(1*time.Second, 10*time.Second)

	// 3. Start Mock Network Traffic Generator
	// This simulates live traffic and attacks so the dashboard is interactive out-of-the-box
	tracker.StartMockGenerator()
	log.Println("Mock packet generator activated successfully.")

	// 4. Initialize and start HTTP WebSocket telemetry server
	srv := server.NewServer(tracker)
	
	webPath, err := filepath.Abs("./web")
	if err != nil {
		webPath = "./web"
	}

	log.Printf("Serving UI assets from: %s", webPath)
	err = srv.Start(":8080", webPath)
	if err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
