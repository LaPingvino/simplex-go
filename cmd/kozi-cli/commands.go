package main

import (
	"errors"
	"fmt"
	"time"
)

func cmdPair(args []string) error {
	if len(args) < 1 {
		return errors.New("pair requires an smp:// invitation URI")
	}
	return errors.New("pair not yet implemented — pending Phase 3 (smp:// invite URI parser)")
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
	code := args[0]
	if len(code) < 4 || len(code) > 16 {
		return fmt.Errorf("plus-code %q has implausible length (expected 4-16 chars)", code)
	}
	s, err := loadState()
	if err != nil {
		return err
	}
	s.CurrentLocation = code
	if err := saveState(s); err != nil {
		return err
	}
	fmt.Printf("Current location set to %s\n", code)
	return nil
}

func cmdProximityWatch(args []string) error {
	if len(args) != 0 {
		return errors.New("proximity-watch takes no arguments")
	}
	return errors.New("proximity-watch not yet implemented — pending Phase 4b (libnotify + SMP queue polling)")
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
