package smp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

// X25519 Diffie-Hellman: shared-secret derivation used for the v7+ deniable
// command authenticator's session secret (`sessSecret` in simplexmq
// Transport.hs:862).
//
//	sessSecret = X25519(clientAuthPriv, serverAuthPub)
//	           = X25519(serverAuthPriv, clientAuthPub)  -- (DH symmetry)
//
// The downstream NaCl crypto_box auth tag is computed per-transmission using
// sessSecret + corrId-nonce + SHA-512(authorizedBytes). That live tag is in
// a follow-up iteration (Phase 2c is just the DH primitive here).

// X25519DeriveShared computes the X25519 shared secret from `priv` (32-byte
// scalar) and `peerPub` (32-byte u-coordinate). Returns the raw 32-byte
// shared secret on success.
//
// SPEC: RFC 7748 §5.
func X25519DeriveShared(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != X25519KeySize {
		return nil, fmt.Errorf("smp: X25519 private key must be %d bytes, got %d", X25519KeySize, len(priv))
	}
	if len(peerPub) != X25519KeySize {
		return nil, fmt.Errorf("smp: X25519 peer public key must be %d bytes, got %d", X25519KeySize, len(peerPub))
	}
	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("smp: parse X25519 private: %w", err)
	}
	pubKey, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("smp: parse X25519 peer pub: %w", err)
	}
	shared, err := privKey.ECDH(pubKey)
	if err != nil {
		// crypto/ecdh returns an error for the all-zero output (low-order
		// point attack). Surface it explicitly.
		return nil, fmt.Errorf("smp: X25519 ECDH: %w", err)
	}
	return shared, nil
}

// X25519KeySize is the byte length of both the X25519 scalar (private key)
// and u-coordinate (public key).
const X25519KeySize = 32

// SessSecret is the X25519-derived shared secret used as the symmetric key
// for v7+ deniable command authentication. Type alias for clarity at call
// sites.
type SessSecret []byte

// DeriveSessSecret is a thin wrapper around X25519DeriveShared that returns
// the typed SessSecret. Use at handshake completion (Dial / NewClient setup)
// to compute the value once and stash it in HandshakeParams for the
// connection's lifetime.
func DeriveSessSecret(ownPriv, peerPub []byte) (SessSecret, error) {
	s, err := X25519DeriveShared(ownPriv, peerPub)
	if err != nil {
		return nil, err
	}
	return SessSecret(s), nil
}

// ErrEmptyX25519Result is wrapped by X25519DeriveShared when the underlying
// ECDH returns the all-zero point (low-order or contributory check failure).
// Kept as a sentinel for callers that want to special-case it.
var ErrEmptyX25519Result = errors.New("smp: X25519 produced empty shared secret (low-order point)")
