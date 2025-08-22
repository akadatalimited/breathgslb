package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestStatsEndpoint verifies that the /stats endpoint returns expected data
// and enforces authentication.
func TestStatsEndpoint(t *testing.T) {
	// Set admin API token and restore after test.
	oldTok := adminAPIToken
	adminAPIToken = "secret"
	t.Cleanup(func() { adminAPIToken = oldTok })

	// Populate statistics data.
	statsMu.Lock()
	latencyRecent = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	memStatsRecent = []runtime.MemStats{{}, {}}
	statsMu.Unlock()

	// Populate supervisor snapshot.
	sup = newSupervisor()
	sup.set("worker", supState{Running: false, Restarts: 3})
	t.Cleanup(func() { sup = nil })

	handler := http.HandlerFunc(statsHandler)

	// Missing auth.
	req := httptest.NewRequest("GET", "/stats", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}

	// Wrong token.
	req = httptest.NewRequest("GET", "/stats", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized with wrong token, got %d", rr.Code)
	}

	// Correct token.
	req = httptest.NewRequest("GET", "/stats", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected OK, got %d", rr.Code)
	}

	var data map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}

	lats, ok := data["latency_ms"].([]any)
	if !ok || len(lats) != 2 {
		t.Fatalf("expected two latency entries, got %v", data["latency_ms"])
	}
	if lats[0].(float64) != 1 || lats[1].(float64) != 2 {
		t.Fatalf("unexpected latency values: %v", lats)
	}

	mems, ok := data["memstats_recent"].([]any)
	if !ok || len(mems) != 2 {
		t.Fatalf("expected two memstats entries, got %v", data["memstats_recent"])
	}

	supData, ok := data["supervisor"].(map[string]any)
	if !ok {
		t.Fatalf("expected supervisor data")
	}
	worker, ok := supData["worker"].(map[string]any)
	if !ok {
		t.Fatalf("expected worker supervisor data")
	}
	if int(worker["restarts"].(float64)) != 3 {
		t.Fatalf("unexpected restart count: %v", worker["restarts"])
	}
}

// TestSupervisorRestart ensures that the supervisor restarts a goroutine
// that exits unexpectedly.
func TestSupervisorRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newSupervisor()
	var runs atomic.Int32
	s.watch(ctx, "task", func() { runs.Add(1) })

	// Wait for at least one restart.
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if runs.Load() < 2 {
		t.Fatalf("goroutine did not restart; runs=%d", runs.Load())
	}

	cancel()
	time.Sleep(100 * time.Millisecond)

	st := s.snapshot()["task"]
	if st.Restarts < 1 {
		t.Fatalf("expected restarts, got %d", st.Restarts)
	}
	if st.LastExit.IsZero() {
		t.Fatalf("expected last exit time to be set")
	}
	if st.Running {
		t.Fatalf("expected task to be stopped")
	}
}
