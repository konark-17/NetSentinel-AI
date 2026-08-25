package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"netsentinel/pkg/sniffer"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow access from standard local addresses
	},
}

// Client represents a connected browser session.
type Client struct {
	conn *websocket.Conn
	send chan []byte
}

// Server holds references to flow tracker, web routing, and sockets.
type Server struct {
	Tracker *sniffer.FlowTracker
	clients map[*Client]bool
	mu      sync.Mutex
}

func NewServer(tracker *sniffer.FlowTracker) *Server {
	return &Server{
		Tracker: tracker,
		clients: make(map[*Client]bool),
	}
}

// Start launches the HTTP routes and websocket listeners.
func (s *Server) Start(addr string, webDir string) error {
	// Serve static files from the frontend folder
	fs := http.FileServer(http.Dir(webDir))
	http.Handle("/", fs)

	// WebSocket endpoint
	http.HandleFunc("/ws", s.handleWebSocket)

	// Spin up the background fan-out routing from the sniffer channels
	go s.listenToSniffer()

	log.Printf("NetSentinel dashboard server starting on http://localhost%s", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Websocket upgrade error: %v", err)
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
	}

	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()

	// Handle outbound writes in a separate goroutine
	go s.writePump(client)

	// Read pump (keeps connection alive, handles close events)
	go s.readPump(client)
}

func (s *Server) readPump(c *Client) {
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
		c.conn.Close()
	}()

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (s *Server) writePump(c *Client) {
	defer func() {
		c.conn.Close()
	}()

	for msg := range c.send {
		err := c.conn.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			break
		}
	}
}

func (s *Server) broadcast(message []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for client := range s.clients {
		select {
		case client.send <- message:
		default:
			close(client.send)
			delete(s.clients, client)
		}
	}
}

// listenToSniffer reads alerts and flows from sniffer and broadcasts them to WebSocket clients.
type WSMessage struct {
	Type string       `json:"type"` // "flow" or "alert"
	Data interface{}  `json:"data"`
}

func (s *Server) listenToSniffer() {
	for {
		select {
		case flow := <-s.Tracker.Broadcast:
			msg := WSMessage{
				Type: "flow",
				Data: flow,
			}
			raw, err := json.Marshal(msg)
			if err == nil {
				s.broadcast(raw)
			}

		case alert := <-s.Tracker.AlertChan:
			msg := WSMessage{
				Type: "alert",
				Data: alert,
			}
			raw, err := json.Marshal(msg)
			if err == nil {
				s.broadcast(raw)
			}
		}
	}
}
