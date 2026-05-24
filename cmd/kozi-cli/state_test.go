package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	want := &State{
		Version:         stateVersion,
		CurrentLocation: "8FVC9G8F",
		Buddies: []Buddy{
			{
				Name:         "alice",
				SharedSecret: "deadbeef",
				SimpleXLink:  "smp://example/queue/alice",
				LastSeenGrid: "8FVC9G8F",
				LastSeenAt:   time.Now().UTC().Truncate(time.Second),
			},
			{
				Name:         "bob",
				SharedSecret: "cafebabe",
			},
		},
	}
	if err := saveState(want); err != nil {
		t.Fatalf("save: %v", err)
	}

	// File created at the expected path with restrictive perms?
	path := filepath.Join(tmp, "kozi", "state.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("state file mode: got %#o want 0600", mode)
	}

	got, err := loadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Version != want.Version {
		t.Errorf("Version: got %d want %d", got.Version, want.Version)
	}
	if got.CurrentLocation != want.CurrentLocation {
		t.Errorf("CurrentLocation: got %q want %q", got.CurrentLocation, want.CurrentLocation)
	}
	if len(got.Buddies) != len(want.Buddies) {
		t.Fatalf("Buddies count: got %d want %d", len(got.Buddies), len(want.Buddies))
	}
	for i, b := range got.Buddies {
		w := want.Buddies[i]
		if b.Name != w.Name || b.SharedSecret != w.SharedSecret || b.SimpleXLink != w.SimpleXLink {
			t.Errorf("Buddies[%d]: got %+v want %+v", i, b, w)
		}
		if !b.LastSeenAt.Equal(w.LastSeenAt) {
			t.Errorf("Buddies[%d].LastSeenAt: got %v want %v", i, b.LastSeenAt, w.LastSeenAt)
		}
	}
}

func TestLoadMissingStateReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	s, err := loadState()
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if s == nil {
		t.Fatal("loadState returned nil")
	}
	if len(s.Buddies) != 0 {
		t.Errorf("Buddies on missing state: got %d want 0", len(s.Buddies))
	}
	if s.Version != stateVersion {
		t.Errorf("Version on missing state: got %d want %d", s.Version, stateVersion)
	}
}

func TestSetLocationAndList(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Inputs longer than proximityPrefixLen are truncated to the coarse
	// neighborhood prefix (privacy default; see normalizePlusCode).
	if err := cmdSetLocation([]string{"8FVC9G8F"}); err != nil {
		t.Fatalf("set-location: %v", err)
	}
	s, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if s.CurrentLocation != "8FVC9G" {
		t.Errorf("CurrentLocation after set: got %q want 8FVC9G (truncated to %d-char prefix)",
			s.CurrentLocation, proximityPrefixLen)
	}

	// Re-set should overwrite, also normalized.
	if err := cmdSetLocation([]string{"8FXX0000"}); err != nil {
		t.Fatal(err)
	}
	s, _ = loadState()
	if s.CurrentLocation != "8FXX00" {
		t.Errorf("CurrentLocation after re-set: got %q want 8FXX00", s.CurrentLocation)
	}

	// list with no buddies should not error.
	if err := cmdList(nil); err != nil {
		t.Errorf("list with no buddies: %v", err)
	}
}

func TestSetLocationBadInput(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := cmdSetLocation([]string{}); err == nil {
		t.Error("no args: expected error")
	}
	if err := cmdSetLocation([]string{"a", "b"}); err == nil {
		t.Error("two args: expected error")
	}
	if err := cmdSetLocation([]string{"abc"}); err == nil {
		t.Error("3-char code: expected error")
	}
	if err := cmdSetLocation([]string{"thisistoolongforaplusscode"}); err == nil {
		t.Error("oversized: expected error")
	}
}

func TestUnpair(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Seed two buddies.
	s := &State{
		Version: stateVersion,
		Buddies: []Buddy{
			{Name: "alice", SharedSecret: "1"},
			{Name: "bob", SharedSecret: "2"},
		},
	}
	if err := saveState(s); err != nil {
		t.Fatal(err)
	}

	if err := cmdUnpair([]string{"alice"}); err != nil {
		t.Fatalf("unpair alice: %v", err)
	}
	s, _ = loadState()
	if len(s.Buddies) != 1 || s.Buddies[0].Name != "bob" {
		t.Fatalf("after unpair alice: %+v", s.Buddies)
	}

	// Unpairing again should error.
	if err := cmdUnpair([]string{"alice"}); err == nil {
		t.Error("unpair missing buddy: expected error")
	}
}

// (TestPairAndProximityWatchAreStubs removed — both cmdPair and
// cmdProximityWatch now have real implementations; pair is exercised in
// pair_test.go and proximity-watch's logic via watchOnce in proximity_test.go.)
