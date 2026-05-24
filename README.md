# simplex-go

A from-scratch Go reimplementation of the [SimpleX](https://simplex.chat) messaging protocol.

**Goal:** wire-compatible with the real SimpleX network, so a Go peer can scan a
real SimpleX invitation link and exchange messages with real SimpleX users.

**Status:** early scaffolding. Nothing works yet.

## Scope

- SMP (Simplex Messaging Protocol) — the TCP+TLS client against SMP relays
- Agent layer — invitation URI → duplex queue pair
- Double ratchet — message E2E encryption
- Invitation URI parser/generator — `smp://...` links compatible with upstream
- A `simplex-cli` for desktop testing

Not in scope (initially): groups, files (XFTP), multi-device sync, profile sync.

## Reference

The canonical implementation is [`simplexmq`](https://github.com/simplex-chat/simplexmq) (Haskell). Protocol specs live in the [`simplex-chat`](https://github.com/simplex-chat/simplex-chat) repo under `docs/`. This project is an independent clean-room implementation, not a port or fork.

## Install (desktop CLI, Linux)

Quick install of `kozi-cli` + `simplex-cli` to `~/.local/bin`:

```sh
git clone https://github.com/LaPingvino/simplex-go
cd simplex-go
make install
```

Override the install prefix with `PREFIX=/usr/local make install` (or any other directory). Make sure `$(PREFIX)/bin` is in your `PATH`.

Try it:

```sh
kozi-cli help
kozi-cli set-location 8FVC9G8F
kozi-cli list
```

`pair` and `proximity-watch` are stubs pending Phase 3 (smp:// URI parser) and Phase 4b (libnotify + SMP polling).

## Companion project

[Kozi](https://github.com/LaPingvino/kozi) is the Android-form proximity-overlap app that will eventually consume `simplex-go` (compiled to an AAR via `gomobile bind`) for its messaging layer. The desktop `kozi-cli` is the same product in a CLI shape — useful for testing the protocol end-to-end without Android tooling.

## License

MIT.

(Upstream simplexmq is AGPL-3.0. Protocol designs are not copyrightable; this
is a clean-room implementation written from spec docs without reading the
Haskell sources for translation, so it is licensable independently. If you
intend to *port* code directly from simplexmq into this repo, that contribution
needs to be relicensed to MIT by the author or kept out.)
