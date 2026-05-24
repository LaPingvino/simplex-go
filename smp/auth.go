package smp

import (
	"crypto/ed25519"
	"errors"
)

// Ed25519Signer adapts an ed25519.PrivateKey to the RcvAuthKey interface.
//
// SPEC: the recipient signs each command with Ed25519 (RFC 8032). The nonce
// argument is ignored — Ed25519 is deterministic and binds the message
// directly. (NaCl crypto_box authenticators use the nonce; see the X25519
// adapter when it lands.)
type Ed25519Signer struct {
	Key ed25519.PrivateKey
}

// Authorize signs `authorized` with the Ed25519 private key. The nonce is
// ignored.
func (s Ed25519Signer) Authorize(authorized []byte, _ CorrID) ([]byte, error) {
	if len(s.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("smp: invalid Ed25519 private key length")
	}
	return ed25519.Sign(s.Key, authorized), nil
}
