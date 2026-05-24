package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LaPingvino/simplex-go/smp"
)

// proximityPrefixLen is the maximum Plus Code prefix length used by kozi-cli
// for proximity matching. 6 chars ≈ 5km × 5km neighborhood-scale — chosen
// to keep the resolution coarse enough that publishing it doesn't dox you.
//
// Reference: https://en.wikipedia.org/wiki/Open_Location_Code#Encoding
// 6 chars covers ~5km² when ignoring the '+' separator.
const proximityPrefixLen = 6

// normalizePlusCode strips the '+' separator, uppercases, and truncates to
// proximityPrefixLen. Both set-location and the proximity comparison pass
// through this so paste-the-full-thing and stored-coarse values still match.
func normalizePlusCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(s, "+", ""))
	if len(s) > proximityPrefixLen {
		s = s[:proximityPrefixLen]
	}
	return s
}

func cmdPair(args []string) error {
	if len(args) != 2 {
		return errors.New("pair requires <buddy-name> <smp-uri>")
	}
	name, uriStr := args[0], args[1]
	if name == "" {
		return errors.New("buddy name must not be empty")
	}

	uri, err := smp.ParseSMPQueueURI(uriStr)
	if err != nil {
		return fmt.Errorf("parse SMP URI: %w", err)
	}

	s, err := loadState()
	if err != nil {
		return err
	}
	for _, b := range s.Buddies {
		if b.Name == name {
			return fmt.Errorf("buddy %q already paired; `kozi-cli unpair %s` first", name, name)
		}
	}

	secret := deriveProximitySecret(uri)
	s.Buddies = append(s.Buddies, Buddy{
		Name:         name,
		SharedSecret: hex.EncodeToString(secret),
		SimpleXLink:  uriStr,
	})
	if err := saveState(s); err != nil {
		return err
	}
	fmt.Printf("Paired %s (server %s:%d)\n", name, uri.Host, uri.Port)
	return nil
}

// deriveProximitySecret derives the per-pair proximity slot-derivation secret
// from the SMP queue URI both peers exchanged. Both sides compute the same
// value from the same URI.
//
// PRIVACY NOTE: anyone who sees the URI in transit can derive this same
// secret, so the proximity beacons are only as private as the channel
// joop used to share the URI. A future iteration will replace this with
// a proper handshake (URI exchange + ephemeral DH key) to provide a
// channel-independent shared secret.
func deriveProximitySecret(uri smp.SMPQueueURI) []byte {
	h := sha256.New()
	h.Write([]byte("kozi-proximity-v1\x00"))
	h.Write(uri.SenderID)
	h.Write(uri.DHPubKey)
	h.Write(uri.ServerFingerprint[:])
	return h.Sum(nil)
}

func cmdList(args []string) error {
	if len(args) != 0 {
		return errors.New("list takes no arguments")
	}
	s, err := loadState()
	if err != nil {
		return err
	}
	if s.CurrentLocation != "" {
		fmt.Printf("Current location: %s\n", s.CurrentLocation)
	} else {
		fmt.Println("Current location: (not set; use `kozi-cli set-location <plus-code>`)")
	}
	if len(s.Buddies) == 0 {
		fmt.Println("\nNo buddies paired. Use `kozi-cli pair <smp-uri>` to add one.")
		return nil
	}
	fmt.Printf("\n%-20s  %-10s  %s\n", "BUDDY", "GRID", "LAST SEEN")
	fmt.Printf("%-20s  %-10s  %s\n", "─────", "────", "─────────")
	for _, b := range s.Buddies {
		grid := b.LastSeenGrid
		if grid == "" {
			grid = "(none)"
		}
		lastSeen := "never"
		if !b.LastSeenAt.IsZero() {
			lastSeen = b.LastSeenAt.Format(time.RFC3339)
		}
		fmt.Printf("%-20s  %-10s  %s\n", b.Name, grid, lastSeen)
	}
	return nil
}

func cmdSetLocation(args []string) error {
	if len(args) != 1 {
		return errors.New("set-location requires exactly one argument: <plus-code>")
	}
	raw := args[0]
	if len(raw) < 4 {
		return fmt.Errorf("plus-code %q too short (need at least 4 chars)", raw)
	}
	if len(raw) > 16 {
		return fmt.Errorf("plus-code %q implausibly long (max 16 chars before normalization)", raw)
	}
	code := normalizePlusCode(raw)
	s, err := loadState()
	if err != nil {
		return err
	}
	s.CurrentLocation = code
	if err := saveState(s); err != nil {
		return err
	}
	if code == strings.ToUpper(strings.ReplaceAll(raw, "+", "")) {
		fmt.Printf("Current location set to %s\n", code)
	} else {
		fmt.Printf("Current location set to %s (truncated from %q to %d-char neighborhood prefix for privacy)\n",
			code, raw, proximityPrefixLen)
	}
	return nil
}

func cmdProximityWatch(args []string) error {
	return cmdProximityWatchReal(args)
}

func cmdUnpair(args []string) error {
	if len(args) != 1 {
		return errors.New("unpair requires exactly one argument: <buddy-name>")
	}
	name := args[0]
	s, err := loadState()
	if err != nil {
		return err
	}
	idx := -1
	for i, b := range s.Buddies {
		if b.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("no buddy named %q", name)
	}
	s.Buddies = append(s.Buddies[:idx], s.Buddies[idx+1:]...)
	if err := saveState(s); err != nil {
		return err
	}
	fmt.Printf("Unpaired %s\n", name)
	return nil
}
