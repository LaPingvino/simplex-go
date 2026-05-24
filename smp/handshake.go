package smp

import (
	"errors"
	"fmt"
)

// SMP handshake messages.
//
// Format derived from simplexmq Transport.hs:535-640 (SMPServerHandshake /
// SMPClientHandshake `Encoding` instances), spec appendix-a of
// simplex-messaging.md.
//
// Layout for the versions we target (v6-v7), batched and ALPN-negotiated:
//
//   ServerHello = VersionRange | ShortString(sessionId) | [v>=V7] authPubKeyOpt
//   ClientHello = Word16(version) | ShortString(keyHash) | [v>=V7] authPubKeyOpt
//
// where authPubKeyOpt for v>=V7 is either:
//   - 0 bytes (no key offered), or
//   - the raw CertChainPubKey / PublicKeyX25519 encoding (length-prefixed
//     internally).
//
// For v<V7 the auth field is omitted entirely.
//
// v12+ adds proxyServer (Bool) and v16+ adds clientService — out of scope
// for the slice 2 handshake. If the server hello carries trailing bytes
// past sessionId on a v7 negotiation, we expose them as AuthPubKeyRaw
// without parsing the cert chain (slice 2 crypto will deserialize).

// SMPServerHandshake is what the server sends first.
type SMPServerHandshake struct {
	VersionRange VersionRange
	SessionID    SessionID
	// AuthPubKeyRaw is the CertChainPubKey blob (parser-internal X.509 + signed
	// pub key). Empty if the server did not offer one. Only present when
	// VersionRange.Max >= V7. Slice 2 will parse this for deniable auth.
	AuthPubKeyRaw []byte
}

// SMPClientHandshake is the client's reply with the chosen version + identity.
type SMPClientHandshake struct {
	Version Version
	// KeyHash is the SHA-256 fingerprint of the offline CA cert (matches the
	// `serverIdentity` in queue URIs and the cert pinning in DialTLS).
	KeyHash KeyHash
	// AuthPubKeyRaw is the optional X25519 public key the client offers for
	// v>=V7 deniable command authentication. Nil = no key offered.
	AuthPubKeyRaw []byte
	// proxyServer (v12+) and clientService (v16+) are out of scope.
}

// EncodeSMPClientHandshake serializes ClientHello for the wire.
//
// SPEC: Haskell instance Encoding SMPClientHandshake (Transport.hs:592).
func EncodeSMPClientHandshake(hs SMPClientHandshake) ([]byte, error) {
	if hs.Version < MinClientVersion {
		return nil, fmt.Errorf("smp: clientHello version %d below minimum %d", hs.Version, MinClientVersion)
	}
	e := NewEncoder()
	e.Word16(uint16(hs.Version))
	if err := e.ShortString(hs.KeyHash[:]); err != nil {
		return nil, fmt.Errorf("smp: clientHello keyHash: %w", err)
	}
	if hs.Version >= VersionV7 && hs.AuthPubKeyRaw != nil {
		if err := e.ShortString(hs.AuthPubKeyRaw); err != nil {
			return nil, fmt.Errorf("smp: clientHello authPubKey: %w", err)
		}
	}
	// proxyServer / clientService omitted (v12+ / v16+).
	return e.Bytes(), nil
}

// DecodeSMPServerHandshake parses ServerHello from the wire.
//
// SPEC: Haskell instance Encoding SMPServerHandshake (Transport.hs:631).
func DecodeSMPServerHandshake(raw []byte) (SMPServerHandshake, error) {
	d := NewDecoder(raw)
	minV, err := d.Word16()
	if err != nil {
		return SMPServerHandshake{}, fmt.Errorf("smp: serverHello minVer: %w", err)
	}
	maxV, err := d.Word16()
	if err != nil {
		return SMPServerHandshake{}, fmt.Errorf("smp: serverHello maxVer: %w", err)
	}
	sessID, err := d.ShortString()
	if err != nil {
		return SMPServerHandshake{}, fmt.Errorf("smp: serverHello sessId: %w", err)
	}
	hs := SMPServerHandshake{
		VersionRange: VersionRange{Min: Version(minV), Max: Version(maxV)},
		SessionID:    append(SessionID(nil), sessID...),
	}
	if Version(maxV) >= VersionV7 && d.Remaining() > 0 {
		// We don't parse the X.509 cert chain here; just hand the rest of the
		// buffer to the caller. Slice 2 crypto will deserialize.
		hs.AuthPubKeyRaw = append([]byte(nil), d.Tail()...)
	}
	return hs, nil
}

// NegotiateVersion returns the highest mutually-supported SMP version
// between our local range [MinClientVersion, MaxClientVersion] and the
// server's offered range. Returns ErrIncompatibleVersion if there is no
// overlap.
//
// SPEC: Haskell compatibleVRange (Version.hs).
func NegotiateVersion(serverRange VersionRange) (Version, error) {
	clientMin, clientMax := MinClientVersion, MaxClientVersion
	lo := clientMin
	if serverRange.Min > lo {
		lo = serverRange.Min
	}
	hi := clientMax
	if serverRange.Max < hi {
		hi = serverRange.Max
	}
	if lo > hi {
		return 0, fmt.Errorf("%w: client=[%d..%d], server=[%d..%d]",
			ErrIncompatibleVersion, clientMin, clientMax, serverRange.Min, serverRange.Max)
	}
	return hi, nil
}

// ErrIncompatibleVersion is returned by NegotiateVersion when there is no
// overlap between client and server SMP version ranges.
var ErrIncompatibleVersion = errors.New("smp: incompatible SMP version range")
