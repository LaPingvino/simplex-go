package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateVersion = 1

// State is the on-disk persisted state for kozi-cli, stored as JSON at
// $XDG_CONFIG_HOME/kozi/state.json.
type State struct {
	Version         int     `json:"version"`
	CurrentLocation string  `json:"current_location,omitempty"`
	Buddies         []Buddy `json:"buddies"`
}

// Buddy is one paired contact.
type Buddy struct {
	Name         string    `json:"name"`
	SharedSecret string    `json:"shared_secret"`
	SimpleXLink  string    `json:"smp_contact_link,omitempty"`
	LastSeenGrid string    `json:"last_seen_grid,omitempty"`
	LastSeenAt   time.Time `json:"last_seen_at,omitempty"`
}

func statePath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(cfg, "kozi", "state.json"), nil
}

func loadState() (*State, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Version: stateVersion, Buddies: []Buddy{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Buddies == nil {
		s.Buddies = []Buddy{}
	}
	return &s, nil
}

func saveState(s *State) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write state %s: %w", path, err)
	}
	return nil
}
