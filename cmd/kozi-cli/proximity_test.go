package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// stubNotifier records (title, body) pairs without invoking notify-send.
type stubNotifier struct {
	mu   sync.Mutex
	sent []string
}

func (s *stubNotifier) Notify(title, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, title+"|"+body)
	return nil
}

func (s *stubNotifier) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestDeriveSlotIDDeterministic(t *testing.T) {
	a := deriveSlotID("deadbeef", "2026-05-24T22")
	b := deriveSlotID("deadbeef", "2026-05-24T22")
	if a != b {
		t.Fatalf("slot ids differ for same input: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("slot id length: got %d want 64 (SHA-256 hex)", len(a))
	}
}

func TestDeriveSlotIDDifferentInputs(t *testing.T) {
	base := deriveSlotID("deadbeef", "2026-05-24T22")
	other := deriveSlotID("cafebabe", "2026-05-24T22")
	if base == other {
		t.Fatal("different secret yields same slot id")
	}
	nextHour := deriveSlotID("deadbeef", "2026-05-24T23")
	if base == nextHour {
		t.Fatal("different hour bucket yields same slot id")
	}
}

func TestHourBucketHourly(t *testing.T) {
	tA := time.Date(2026, 5, 24, 22, 5, 0, 0, time.UTC)
	tB := time.Date(2026, 5, 24, 22, 59, 0, 0, time.UTC)
	tC := time.Date(2026, 5, 24, 23, 0, 0, 0, time.UTC)
	if hourBucket(tA) != hourBucket(tB) {
		t.Errorf("two times within same hour should bucket together: %q vs %q", hourBucket(tA), hourBucket(tB))
	}
	if hourBucket(tA) == hourBucket(tC) {
		t.Errorf("hour boundary should switch bucket: both %q", hourBucket(tA))
	}
}

func TestWatchOnceErrorsWithoutLocation(t *testing.T) {
	s := &State{Version: stateVersion}
	notifier := &stubNotifier{}
	_, err := watchOnce(s, WatchConfig{Notifier: notifier, Now: time.Now})
	if err == nil {
		t.Fatal("no location: expected error")
	}
	if notifier.count() != 0 {
		t.Errorf("no location: notifier should not fire, got %d", notifier.count())
	}
}

func TestWatchOnceNoMatches(t *testing.T) {
	s := &State{
		Version:         stateVersion,
		CurrentLocation: "8FVC9G8F",
		Buddies: []Buddy{
			{Name: "alice", SharedSecret: "deadbeef", LastSeenGrid: "8FXX0000"}, // different grid
			{Name: "bob", SharedSecret: "cafebabe"},                            // no grid recorded
		},
	}
	notifier := &stubNotifier{}
	matches, err := watchOnce(s, WatchConfig{Notifier: notifier, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("no matches expected, got %v", matches)
	}
	if notifier.count() != 0 {
		t.Errorf("notifier fired %d times, expected 0", notifier.count())
	}
}

func TestWatchOnceMatchFires(t *testing.T) {
	s := &State{
		Version:         stateVersion,
		CurrentLocation: "8FVC9G8F",
		Buddies: []Buddy{
			{Name: "alice", SharedSecret: "deadbeef", LastSeenGrid: "8FVC9G8F"}, // match
			{Name: "bob", SharedSecret: "cafebabe", LastSeenGrid: "8FXX0000"},   // no match
		},
	}
	notifier := &stubNotifier{}
	matches, err := watchOnce(s, WatchConfig{Notifier: notifier, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != "alice" {
		t.Fatalf("matches: got %v want [alice]", matches)
	}
	if notifier.count() != 1 {
		t.Fatalf("notifier fires: got %d want 1", notifier.count())
	}
	if !strings.Contains(notifier.sent[0], "alice") || !strings.Contains(notifier.sent[0], "8FVC9G") {
		t.Errorf("notification body missing buddy/normalized-grid: %q", notifier.sent[0])
	}
}

func TestWatchOnceMultipleMatches(t *testing.T) {
	s := &State{
		Version:         stateVersion,
		CurrentLocation: "8FVC9G8F",
		Buddies: []Buddy{
			{Name: "alice", SharedSecret: "1", LastSeenGrid: "8FVC9G8F"},
			{Name: "bob", SharedSecret: "2", LastSeenGrid: "8FVC9G8F"},
		},
	}
	notifier := &stubNotifier{}
	matches, _ := watchOnce(s, WatchConfig{Notifier: notifier, Now: time.Now})
	if len(matches) != 2 || notifier.count() != 2 {
		t.Fatalf("expected 2 matches+notifies, got matches=%v count=%d", matches, notifier.count())
	}
}
