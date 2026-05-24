package smp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func newX25519Pair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	curve := ecdh.X25519()
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

func TestX25519AuthSignerRoundTrip(t *testing.T) {
	// Server keypair (peer in client's view); client keypair (peer in server's view).
	srvPriv, srvPub := newX25519Pair(t)
	cliPriv, cliPub := newX25519Pair(t)

	msg := []byte("authorized transmission bytes")
	var nonce CorrID
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	// Client signs (sees server's pub key as the peer).
	signer := X25519AuthSigner{Priv: cliPriv, PeerPub: srvPub}
	tag, err := signer.Authorize(msg, nonce)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(tag) != CbAuthenticatorSize {
		t.Fatalf("tag size: got %d want %d", len(tag), CbAuthenticatorSize)
	}

	// Server verifies (sees client's pub key as the peer).
	ok, err := VerifyCbAuth(cliPub, srvPriv, nonce, tag, msg)
	if err != nil {
		t.Fatalf("VerifyCbAuth: %v", err)
	}
	if !ok {
		t.Fatal("VerifyCbAuth: expected true, got false")
	}
}

func TestX25519AuthSignerTamperDetection(t *testing.T) {
	srvPriv, srvPub := newX25519Pair(t)
	cliPriv, cliPub := newX25519Pair(t)
	msg := []byte("original message")
	var nonce CorrID
	signer := X25519AuthSigner{Priv: cliPriv, PeerPub: srvPub}
	tag, err := signer.Authorize(msg, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper the tag.
	tag[0] ^= 0xFF
	ok, err := VerifyCbAuth(cliPub, srvPriv, nonce, tag, msg)
	if err != nil {
		t.Fatalf("VerifyCbAuth tampered: %v", err)
	}
	if ok {
		t.Fatal("tampered tag verified — should have failed")
	}

	// Restore tag, tamper message.
	tag[0] ^= 0xFF
	ok, _ = VerifyCbAuth(cliPub, srvPriv, nonce, tag, []byte("different message"))
	if ok {
		t.Fatal("verified with different message — should have failed")
	}

	// Restore message, tamper nonce.
	nonce[0] ^= 0xFF
	ok, _ = VerifyCbAuth(cliPub, srvPriv, nonce, tag, msg)
	if ok {
		t.Fatal("verified with different nonce — should have failed")
	}
}

func TestX25519AuthSignerNonceMatters(t *testing.T) {
	// Unlike Ed25519, NaCl crypto_box auth IS nonce-dependent — different
	// nonces over the same message yield different tags.
	srvPriv, srvPub := newX25519Pair(t)
	cliPriv, _ := newX25519Pair(t)
	signer := X25519AuthSigner{Priv: cliPriv, PeerPub: srvPub}
	_ = srvPriv

	msg := []byte("same message")
	var n1, n2 CorrID
	for i := range n1 {
		n1[i] = byte(i)
		n2[i] = byte(i + 100)
	}
	t1, err := signer.Authorize(msg, n1)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := signer.Authorize(msg, n2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(t1, t2) {
		t.Fatal("same tag across different nonces — adapter is nonce-blind")
	}
}

func TestX25519AuthSignerLayoutMatchesHaskell(t *testing.T) {
	// Confirm the tag is exactly (16-byte Poly1305 tag || 64-byte encrypted
	// SHA-512 digest), matching simplexmq Crypto.hs cryptoBox layout
	// (tag <> ciphertext).
	srvPriv, srvPub := newX25519Pair(t)
	cliPriv, _ := newX25519Pair(t)
	signer := X25519AuthSigner{Priv: cliPriv, PeerPub: srvPub}
	_ = srvPriv

	msg := []byte("payload")
	var nonce CorrID
	tag, err := signer.Authorize(msg, nonce)
	if err != nil {
		t.Fatal(err)
	}

	if len(tag) != 16+64 {
		t.Fatalf("tag layout: %d bytes (want 16+64=80)", len(tag))
	}

	// secretbox.Open should recover SHA-512(msg) exactly.
	shared, err := X25519DeriveShared(cliPriv, srvPub)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], shared)
	var n [24]byte
	copy(n[:], nonce[:])
	plain, ok := secretbox.Open(nil, tag, &n, &key)
	if !ok {
		t.Fatal("secretbox.Open failed on our own tag")
	}
	want := sha512.Sum512(msg)
	if !bytes.Equal(plain, want[:]) {
		t.Fatalf("decrypted plaintext is not SHA-512(msg):\n  got  %x\n  want %x", plain, want)
	}
}

func TestX25519AuthSignerBadKeys(t *testing.T) {
	_, srvPub := newX25519Pair(t)
	cases := []struct {
		name        string
		priv, peer  []byte
	}{
		{"priv too short", []byte{1, 2, 3}, srvPub},
		{"priv nil", nil, srvPub},
		{"peer too long", make([]byte, X25519KeySize), make([]byte, X25519KeySize+1)},
		{"peer nil", make([]byte, X25519KeySize), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := X25519AuthSigner{Priv: c.priv, PeerPub: c.peer}
			_, err := s.Authorize([]byte("msg"), CorrID{})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestX25519AuthSignerCrossPartyVerify(t *testing.T) {
	// The whole point of Diffie-Hellman: even though only one side knows
	// each private key, both can independently compute the same shared
	// secret and so both can sign+verify each other's messages.
	srvPriv, srvPub := newX25519Pair(t)
	cliPriv, cliPub := newX25519Pair(t)
	msg := []byte("hello server")
	var nonce CorrID
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}

	// Client signs to server.
	cli := X25519AuthSigner{Priv: cliPriv, PeerPub: srvPub}
	tag, err := cli.Authorize(msg, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifies using its own priv + client's pub.
	ok, err := VerifyCbAuth(cliPub, srvPriv, nonce, tag, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("server verify of client-signed tag: expected true")
	}
}

// Compile-time check.
var _ RcvAuthKey = X25519AuthSigner{}

func TestCbAuthenticatorSizeConstant(t *testing.T) {
	if CbAuthenticatorSize != 80 {
		t.Errorf("CbAuthenticatorSize: got %d want 80 (16 + 64)", CbAuthenticatorSize)
	}
}

