package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type event struct {
	ID        uint64 `json:"id"`
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Data      any    `json:"data"`
}

type eventHub struct {
	mu          sync.Mutex
	next        uint64
	ring        []event
	subscribers map[chan struct{}]bool
}

func newEventHub() *eventHub {
	return &eventHub{subscribers: map[chan struct{}]bool{}}
}

func (h *eventHub) publish(kind, session string, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	h.ring = append(h.ring, event{h.next, kind, session, data})
	if len(h.ring) > 256 {
		h.ring = h.ring[len(h.ring)-256:]
	}
	for ch := range h.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (h *eventHub) read(after uint64) ([]event, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	gap := len(h.ring) > 0 && after > 0 && after < h.ring[0].ID-1
	events := []event{}
	for _, entry := range h.ring {
		if entry.ID > after {
			events = append(events, entry)
		}
	}
	return events, gap
}

func (h *eventHub) serve(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subscribers[ch] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	send := func() bool {
		entries, gap := h.read(after)
		if gap {
			data, _ := json.Marshal(event{Type: "gap", Data: map[string]any{"reason": "event cursor expired; reload state"}})
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return false
			}
		}
		for _, entry := range entries {
			data, _ := json.Marshal(entry)
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", entry.ID, data); err != nil {
				return false
			}
			after = entry.ID
		}
		flusher.Flush()
		return true
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			if !send() {
				return
			}
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": transport connected\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
