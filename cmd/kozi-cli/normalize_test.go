package main

import (
	"testing"
	"time"
)

var nowFixed = func() time.Time { return time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC) }

func TestNormalizePlusCode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"8FVC9G8F+P0Q", "8FVC9G"},        // full 11-char code -> 6
		{"8fvc9g8f+p0q", "8FVC9G"},        // lowercase normalized
		{"8FVC9G", "8FVC9G"},              // already 6 chars, no-op
		{"8FVC9G8F", "8FVC9G"},            // 8-char prefix -> 6
		{"8FVC", "8FVC"},                  // shorter than 6 -> unchanged
		{"", ""},                          // empty -> empty
		{"+", ""},                         // only separator
		{"++8FVC9G8F++", "8FVC9G"},        // multiple separators
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := normalizePlusCode(c.in)
			if got != c.want {
				t.Errorf("normalizePlusCode(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSetLocationNormalizes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Paste a high-precision code, expect it to land coarse.
	if err := cmdSetLocation([]string{"8FVC9G8F+P0Q"}); err != nil {
		t.Fatalf("set-location: %v", err)
	}
	s, _ := loadState()
	if s.CurrentLocation != "8FVC9G" {
		t.Errorf("stored location: got %q want %q (should be truncated to %d chars)",
			s.CurrentLocation, "8FVC9G", proximityPrefixLen)
	}

	// Lowercase + separator should still normalize.
	if err := cmdSetLocation([]string{"8fxx0000+pq"}); err != nil {
		t.Fatal(err)
	}
	s, _ = loadState()
	if s.CurrentLocation != "8FXX00" {
		t.Errorf("stored: got %q want 8FXX00", s.CurrentLocation)
	}
}

func TestSetLocationRejectsTooLongRaw(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	// 17 chars raw — sanity guardrail above normalization.
	long := "8FVC9G8F+P0QABCDE"
	if err := cmdSetLocation([]string{long}); err == nil {
		t.Fatal("17-char raw input: expected error")
	}
}

func TestWatchOnceNormalizesBothSides(t *testing.T) {
	s := &State{
		Version:         stateVersion,
		CurrentLocation: "8FVC9G",         // stored coarse
		Buddies: []Buddy{
			{Name: "alice", SharedSecret: "1", LastSeenGrid: "8FVC9G8F+P0Q"}, // stored fine — should still match via normalization
			{Name: "bob", SharedSecret: "2", LastSeenGrid: "8FXX00"},          // different neighborhood
		},
	}
	notifier := &stubNotifier{}
	matches, err := watchOnce(s, WatchConfig{Notifier: notifier, Now: nowFixed})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != "alice" {
		t.Errorf("matches: got %v want [alice]", matches)
	}
}
