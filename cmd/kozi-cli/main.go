// Command kozi-cli is the desktop form of Kozi — a thin proximity overlay
// on top of SimpleX. It lets you pair with buddies via SimpleX invitation
// URIs, set your current Plus Code grid manually, and run a local daemon
// that publishes/polls rotating proximity-slot beacons and fires desktop
// notifications on grid match.
//
// Status: early development. Subcommands `pair` and `proximity-watch` are
// stubs pending Phase 3 (smp:// URI parser) and Phase 4b (libnotify + SMP
// queue polling). `list`, `set-location`, and `unpair` work today.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "pair":
		err = cmdPair(args)
	case "list":
		err = cmdList(args)
	case "set-location":
		err = cmdSetLocation(args)
	case "proximity-watch":
		err = cmdProximityWatch(args)
	case "unpair":
		err = cmdUnpair(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	case "version", "-V", "--version":
		fmt.Println("kozi-cli", version)
		return
	default:
		fmt.Fprintf(os.Stderr, "kozi-cli: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kozi-cli:", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `kozi-cli — proximity overlay on SimpleX (early development)

Usage:
  kozi-cli <command> [args]

Commands:
  pair <smp-uri>             Accept a SimpleX invitation to pair with a buddy [stub: Phase 3]
  list                       List paired buddies and current location
  set-location <plus-code>   Set your current Plus Code grid (8 chars = ~250m)
  proximity-watch            Run the proximity-overlap daemon [stub: Phase 4b]
  unpair <buddy-name>        Remove a paired buddy
  help                       Show this help
  version                    Show version

State file: $XDG_CONFIG_HOME/kozi/state.json (default: ~/.config/kozi/state.json)
`)
}
