package smp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestEd25519SignerRoundTrip(t *testing.T) {
	// Deterministic keypair from a fixed seed.
	seed := bytes.Repeat([]byte{0xAB}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	signer := Ed25519Signer{Key: priv}
	msg := []byte("authorized-bytes-go-here")
	var nonce CorrID // ignored for Ed25519

	sig, err := signer.Authorize(msg, nonce)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig size: got %d want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("Ed25519 verify failed on fresh signature")
	}

	// Tamper detection.
	sig[0] ^= 0xFF
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("tampered signature verified — should have failed")
	}
}

func TestEd25519SignerNonceIgnored(t *testing.T) {
	// Signing the same message with two different nonces must produce the
	// same signature (Ed25519 is deterministic; our adapter must not mix
	// the nonce in).
	seed := bytes.Repeat([]byte{0xCD}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	signer := Ed25519Signer{Key: priv}
	msg := []byte("same message")

	var n1 CorrID
	for i := range n1 {
		n1[i] = byte(i)
	}
	var n2 CorrID
	for i := range n2 {
		n2[i] = byte(i + 100)
	}

	s1, err := signer.Authorize(msg, n1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := signer.Authorize(msg, n2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("Ed25519 sig differs across nonces — adapter is leaking nonce into signature")
	}
}

func TestEd25519SignerBadKey(t *testing.T) {
	signer := Ed25519Signer{Key: []byte{0x01, 0x02, 0x03}} // wrong size
	_, err := signer.Authorize([]byte("msg"), CorrID{})
	if err == nil {
		t.Fatal("Authorize with short key: expected error, got nil")
	}
}

// TestEd25519SignerKAT_RFC8032 verifies our adapter against RFC 8032 test
// vector "TEST 1" (Section 7.1).
//
//	SECRET KEY (seed): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
//	PUBLIC KEY:        d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
//	MESSAGE:           (empty)
//	SIGNATURE:         e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
//
// Source: https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
func TestEd25519SignerKAT_RFC8032(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantSig, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	wantPub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, wantPub) {
		t.Fatalf("pubkey from seed: got %x want %x", pub, wantPub)
	}

	signer := Ed25519Signer{Key: priv}
	sig, err := signer.Authorize([]byte{}, CorrID{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("RFC 8032 TEST 1 signature mismatch:\n  got  %x\n  want %x", sig, wantSig)
	}
}

// TestEd25519SignerImplementsRcvAuthKey is a compile-time check.
var _ RcvAuthKey = Ed25519Signer{}
