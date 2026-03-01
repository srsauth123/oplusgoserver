package handler

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// LogBroadcaster captures log output and streams to SSE clients
type LogBroadcaster struct {
	mu       sync.RWMutex
	clients  map[chan string]bool
	buffer   []string
	bufLimit int
}

var GlobalLogBroadcaster = &LogBroadcaster{
	clients:  make(map[chan string]bool),
	bufLimit: 500,
}

// Write implements io.Writer for log.SetOutput
func (lb *LogBroadcaster) Write(p []byte) (n int, err error) {
	msg := string(p)
	lb.mu.Lock()
	lb.buffer = append(lb.buffer, msg)
	if len(lb.buffer) > lb.bufLimit {
		lb.buffer = lb.buffer[len(lb.buffer)-lb.bufLimit:]
	}
	// copy clients to avoid holding lock while sending
	clients := make([]chan string, 0, len(lb.clients))
	for ch := range lb.clients {
		clients = append(clients, ch)
	}
	lb.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- msg:
		default:
			// drop if client is slow
		}
	}
	return len(p), nil
}

func (lb *LogBroadcaster) Subscribe() chan string {
	ch := make(chan string, 100)
	lb.mu.Lock()
	lb.clients[ch] = true
	lb.mu.Unlock()
	return ch
}

func (lb *LogBroadcaster) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.clients, ch)
	lb.mu.Unlock()
	close(ch)
}

func (lb *LogBroadcaster) GetBuffer() []string {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	cp := make([]string, len(lb.buffer))
	copy(cp, lb.buffer)
	return cp
}

// InitLogBroadcaster sets up log output to both stdout and broadcaster
func InitLogBroadcaster() {
	mw := io.MultiWriter(os.Stdout, GlobalLogBroadcaster)
	log.SetOutput(mw)
	log.SetFlags(log.LstdFlags)
}

// LogStreamAuth supports token via query param (EventSource can't set headers)
func (h *AdminHandler) LogStreamAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" || !h.verifyJWT(token) {
			adminErr(w, http.StatusUnauthorized, "无效或过期 Token")
			return
		}
		next(w, r)
	}
}

// SSE endpoint handler
func (h *AdminHandler) LogStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Send buffered history first
	history := GlobalLogBroadcaster.GetBuffer()
	for _, line := range history {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	flusher.Flush()

	// Subscribe to new logs
	ch := GlobalLogBroadcaster.Subscribe()
	defer GlobalLogBroadcaster.Unsubscribe(ch)

	// Keep-alive ticker
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
