package smp

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// X25519AuthSigner adapts a per-pair X25519 key + the server's auth pub key
// to the RcvAuthKey interface, producing v7+ SMP deniable authenticators.
//
// SPEC: simplexmq/src/Simplex/Messaging/Crypto.hs:1366
//
//	cbAuthenticate k pk nonce msg = CbAuthenticator $ cbEncryptNoPad (dh' k pk) nonce (sha512Hash msg)
//
// Concretely: the 80-byte tag is
//
//	secretbox.Seal(nil, SHA-512(authorized), corrId, X25519DH(ownPriv, peerPub))
//
// Layout: 16-byte Poly1305 tag || 64-byte XSalsa20-encrypted SHA-512 digest.
//
// "Deniable" because verification requires the private DH input — the
// recipient can authenticate the sender but no third party can be
// convinced the sender produced this message (unlike a signature).
type X25519AuthSigner struct {
	// Priv is the 32-byte X25519 scalar held by this side of the queue
	// (the recipient's auth private key, for recipient commands; the
	// sender's auth private key, for SEND).
	Priv []byte
	// PeerPub is the 32-byte X25519 public key of the SMP server's
	// authentication keypair (offered in the SMP server hello's
	// CertChainPubKey block).
	PeerPub []byte
}

// Authorize produces an 80-byte deniable authenticator over `authorized`,
// using `nonce` (the transmission's corrId) as the 24-byte XSalsa20 nonce.
func (s X25519AuthSigner) Authorize(authorized []byte, nonce CorrID) ([]byte, error) {
	if len(s.Priv) != X25519KeySize {
		return nil, fmt.Errorf("smp: X25519 priv must be %d bytes, got %d", X25519KeySize, len(s.Priv))
	}
	if len(s.PeerPub) != X25519KeySize {
		return nil, fmt.Errorf("smp: X25519 peer pub must be %d bytes, got %d", X25519KeySize, len(s.PeerPub))
	}
	shared, err := X25519DeriveShared(s.Priv, s.PeerPub)
	if err != nil {
		return nil, fmt.Errorf("smp: derive sessSecret: %w", err)
	}
	digest := sha512.Sum512(authorized)

	var key [32]byte
	copy(key[:], shared)
	var n [24]byte
	copy(n[:], nonce[:])

	tag := secretbox.Seal(nil, digest[:], &n, &key)
	if len(tag) != CbAuthenticatorSize {
		return nil, fmt.Errorf("smp: unexpected tag size %d (want %d)", len(tag), CbAuthenticatorSize)
	}
	return tag, nil
}

// VerifyCbAuth verifies a deniable authenticator. Returns true iff
// `tag == secretbox.Seal(nil, SHA-512(authorized), nonce, DH(ownPriv, peerPub))`.
// Used by the server side (and by tests).
func VerifyCbAuth(peerPub, ownPriv []byte, nonce CorrID, tag, authorized []byte) (bool, error) {
	if len(tag) != CbAuthenticatorSize {
		return false, fmt.Errorf("smp: tag must be %d bytes, got %d", CbAuthenticatorSize, len(tag))
	}
	shared, err := X25519DeriveShared(ownPriv, peerPub)
	if err != nil {
		return false, fmt.Errorf("smp: derive sessSecret: %w", err)
	}
	digest := sha512.Sum512(authorized)

	var key [32]byte
	copy(key[:], shared)
	var n [24]byte
	copy(n[:], nonce[:])

	plain, ok := secretbox.Open(nil, tag, &n, &key)
	if !ok {
		return false, nil
	}
	if len(plain) != len(digest) {
		return false, nil
	}
	for i := range plain {
		if plain[i] != digest[i] {
			return false, nil
		}
	}
	return true, nil
}

// CbAuthenticatorSize is the on-wire size of the deniable authenticator:
// 16-byte Poly1305 tag + 64-byte XSalsa20-encrypted SHA-512 digest = 80.
const CbAuthenticatorSize = 16 + sha512.Size

// ErrCbVerifyFailed is a sentinel for callers that want to special-case
// authentication failure as distinct from other errors.
var ErrCbVerifyFailed = errors.New("smp: crypto_box authenticator verification failed")
