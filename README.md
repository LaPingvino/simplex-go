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

## Companion project

[Kozi](https://github.com/LaPingvino/kozi) is an Android proximity-overlap app that consumes `simplex-go` (compiled to an AAR via `gomobile bind`) for its messaging layer.

## License

MIT.

(Upstream simplexmq is AGPL-3.0. Protocol designs are not copyrightable; this
is a clean-room implementation written from spec docs without reading the
Haskell sources for translation, so it is licensable independently. If you
intend to *port* code directly from simplexmq into this repo, that contribution
needs to be relicensed to MIT by the author or kept out.)
