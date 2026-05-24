package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Notifier abstracts desktop notifications so tests can intercept without
// invoking the real notify-send binary.
type Notifier interface {
	Notify(title, body string) error
}

// notifySendNotifier shells out to libnotify's notify-send. Available on
// most Linux desktops (KDE, GNOME, XFCE, sway with mako, etc.).
type notifySendNotifier struct{}

func (notifySendNotifier) Notify(title, body string) error {
	cmd := exec.Command("notify-send", "--app-name=kozi-cli", "--category=im.received", title, body)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("notify-send: %w (is libnotify installed?)", err)
	}
	return nil
}

// WatchConfig configures one tick or the periodic loop.
type WatchConfig struct {
	Interval time.Duration
	Notifier Notifier
	Now      func() time.Time
}

func defaultWatchConfig() WatchConfig {
	return WatchConfig{
		Interval: 15 * time.Minute,
		Notifier: notifySendNotifier{},
		Now:      time.Now,
	}
}

// deriveSlotID derives the rotating slot identifier for one buddy on one
// hourly window. Both peers compute the same value from the same shared
// secret + UTC hour, so it doubles as a coordination address into whatever
// queue/storage backend publishes proximity beacons.
//
// SPEC (from kozi-vision): SlotID = Hash(sharedSecret || dateString)
// where dateString rotates hourly (UTC).
//
// Returns 64 hex chars (full SHA-256). Storage backends can truncate as
// needed for their address space.
func deriveSlotID(sharedSecretHex, hourBucket string) string {
	h := sha256.New()
	h.Write([]byte(sharedSecretHex))
	h.Write([]byte(":"))
	h.Write([]byte(hourBucket))
	return hex.EncodeToString(h.Sum(nil))
}

// hourBucket formats a time as the per-hour slot bucket used by deriveSlotID.
// Granularity is hourly so paired devices on different clocks within a few
// minutes still agree.
func hourBucket(t time.Time) string {
	return t.UTC().Format("2006-01-02T15")
}

// watchOnce runs one proximity-check tick: for every paired buddy, derives
// the current hourly slot id and (currently STUB) checks whether the buddy
// is in joop's grid. Real SMP queue publish/poll lands once Phase 2d (NaCl
// auth tag) and a real Client.Send/Subscribe wiring exist.
//
// Returns the names of buddies that triggered a notification this tick.
func watchOnce(s *State, cfg WatchConfig) ([]string, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Notifier == nil {
		// Don't default to notify-send here — tests would silently invoke
		// the real notifier and hang (no D-Bus session). Production callers
		// pass defaultWatchConfig() which fills it in.
		return nil, errors.New("watchOnce: cfg.Notifier is nil")
	}
	if s.CurrentLocation == "" {
		return nil, errors.New("current location not set; use `kozi-cli set-location <plus-code>`")
	}

	now := cfg.Now()
	bucket := hourBucket(now)
	matches := make([]string, 0, len(s.Buddies))

	myGrid := normalizePlusCode(s.CurrentLocation)
	for _, b := range s.Buddies {
		_ = deriveSlotID(b.SharedSecret, bucket) // TODO(phase-2d): publish + poll via slot

		// STUB: in lieu of a real SMP poll for the buddy's beacon, we
		// match on LastSeenGrid persisted in state (whichever value a
		// future SMP receiver wrote there). For local self-testing,
		// set s.Buddies[i].LastSeenGrid manually in state.json. Both
		// sides normalize so a paste-the-full-thing on one side still
		// matches the coarse stored value.
		if b.LastSeenGrid == "" {
			continue
		}
		if normalizePlusCode(b.LastSeenGrid) != myGrid {
			continue
		}
		matches = append(matches, b.Name)
		title := "Kozi: proximity match"
		body := fmt.Sprintf("%s might be nearby (neighborhood %s)", b.Name, myGrid)
		if err := cfg.Notifier.Notify(title, body); err != nil {
			return matches, fmt.Errorf("notify %s: %w", b.Name, err)
		}
	}
	return matches, nil
}

// runWatchLoop is the daemon body: tick immediately, then on every Interval.
// Stops cleanly on SIGINT/SIGTERM or when ctx is done.
func runWatchLoop(ctx context.Context, cfg WatchConfig) error {
	tick := func() {
		s, err := loadState()
		if err != nil {
			fmt.Fprintln(os.Stderr, "watch: load state:", err)
			return
		}
		matches, err := watchOnce(s, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watch:", err)
			return
		}
		if len(matches) > 0 {
			fmt.Printf("[%s] proximity match: %v\n", cfg.Now().Format(time.RFC3339), matches)
		}
	}

	tick() // immediate first check, no need to wait for the first ticker fire

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			tick()
		}
	}
}

// cmdProximityWatch (production) — wires defaultWatchConfig and signal-based
// cancellation, then delegates to runWatchLoop.
func cmdProximityWatchReal(args []string) error {
	if len(args) != 0 {
		return errors.New("proximity-watch takes no arguments")
	}
	cfg := defaultWatchConfig()
	fmt.Printf("Proximity watch starting (interval %v, hourly slot id). Ctrl-C to stop.\n", cfg.Interval)
	fmt.Println("NOTE: SMP queue polling is STUBBED — matches require manually setting")
	fmt.Println("      Buddy.LastSeenGrid in state.json for now. Real polling lands with Phase 2d.")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := runWatchLoop(ctx, cfg); err != nil {
		return err
	}
	fmt.Println("\nProximity watch stopped.")
	return nil
}
