package smp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestX25519KAT_RFC7748_TestVector1 verifies our X25519 DH against the first
// canonical KAT in RFC 7748 §5.2.
//
//	Scalar (priv):   a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
//	U-coord (peer):  e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
//	Output:          c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
//
// Source: https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
func TestX25519KAT_RFC7748_TestVector1(t *testing.T) {
	priv, _ := hex.DecodeString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	pub, _ := hex.DecodeString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	want, _ := hex.DecodeString("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

	got, err := X25519DeriveShared(priv, pub)
	if err != nil {
		t.Fatalf("X25519DeriveShared: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 7748 TV1 mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestX25519KAT_RFC7748_TestVector2 — second KAT from the same section.
//
//	Scalar:    4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
//	U-coord:   e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
//	Output:    95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
func TestX25519KAT_RFC7748_TestVector2(t *testing.T) {
	priv, _ := hex.DecodeString("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
	pub, _ := hex.DecodeString("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
	want, _ := hex.DecodeString("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

	got, err := X25519DeriveShared(priv, pub)
	if err != nil {
		t.Fatalf("X25519DeriveShared: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 7748 TV2 mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func TestX25519DHSymmetry(t *testing.T) {
	// DH is symmetric: DH(a_priv, b_pub) == DH(b_priv, a_pub).
	// Use two RFC 7748 ECDH test vectors' scalars + their corresponding pubs.
	aPriv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bPriv, _ := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

	// Derive public keys from each private (the public is X25519(priv, basepoint)).
	// RFC 7748 §6.1 gives us:
	aPub, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bPub, _ := hex.DecodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantShared, _ := hex.DecodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	ab, err := X25519DeriveShared(aPriv, bPub)
	if err != nil {
		t.Fatalf("DH(a, B): %v", err)
	}
	ba, err := X25519DeriveShared(bPriv, aPub)
	if err != nil {
		t.Fatalf("DH(b, A): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("DH not symmetric:\n  DH(a,B) = %x\n  DH(b,A) = %x", ab, ba)
	}
	if !bytes.Equal(ab, wantShared) {
		t.Fatalf("DH != RFC 7748 §6.1 shared secret:\n  got  %x\n  want %x", ab, wantShared)
	}
}

func TestX25519WrongLengthInputs(t *testing.T) {
	good := make([]byte, X25519KeySize)
	good[0] = 0xAB
	tooLong := make([]byte, X25519KeySize+1)

	if _, err := X25519DeriveShared(good[:31], good); err == nil {
		t.Error("priv 31 bytes: expected error")
	}
	if _, err := X25519DeriveShared(good, tooLong); err == nil {
		t.Error("pub 33 bytes: expected error")
	}
	if _, err := X25519DeriveShared(good[:0], good); err == nil {
		t.Error("empty priv: expected error")
	}
	if _, err := X25519DeriveShared(good, nil); err == nil {
		t.Error("nil pub: expected error")
	}
}

func TestDeriveSessSecretWrapper(t *testing.T) {
	priv, _ := hex.DecodeString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	pub, _ := hex.DecodeString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	want, _ := hex.DecodeString("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

	got, err := DeriveSessSecret(priv, pub)
	if err != nil {
		t.Fatalf("DeriveSessSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SessSecret mismatch:\n  got  %x\n  want %x", got, want)
	}
}
