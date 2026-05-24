package smp

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeSMPClientHandshakeV7NoAuthKey(t *testing.T) {
	var kh KeyHash
	for i := range kh {
		kh[i] = 0xAB
	}
	hs := SMPClientHandshake{
		Version: VersionV7,
		KeyHash: kh,
		// AuthPubKeyRaw nil -> not encoded
	}
	got, err := EncodeSMPClientHandshake(hs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Layout: Word16(7) | ShortString(32 bytes 0xAB)
	want := []byte{0x00, 0x07, 0x20}
	want = append(want, bytes.Repeat([]byte{0xAB}, 32)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("v7 no-authkey clientHello:\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeSMPClientHandshakeV7WithAuthKey(t *testing.T) {
	var kh KeyHash
	for i := range kh {
		kh[i] = 0xCD
	}
	authKey := bytes.Repeat([]byte{0xEE}, 32) // pretend X25519 pubkey blob
	hs := SMPClientHandshake{
		Version:       VersionV7,
		KeyHash:       kh,
		AuthPubKeyRaw: authKey,
	}
	got, err := EncodeSMPClientHandshake(hs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Layout: Word16(7) | ShortString(keyHash) | ShortString(authKey)
	want := []byte{0x00, 0x07, 0x20}
	want = append(want, bytes.Repeat([]byte{0xCD}, 32)...)
	want = append(want, byte(32))
	want = append(want, authKey...)
	if !bytes.Equal(got, want) {
		t.Fatalf("v7 with-authkey clientHello:\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeSMPClientHandshakeV6NoAuthEvenIfProvided(t *testing.T) {
	var kh KeyHash
	hs := SMPClientHandshake{
		Version:       VersionV6,
		KeyHash:       kh,
		AuthPubKeyRaw: bytes.Repeat([]byte{0xFF}, 32), // must be ignored on v6
	}
	got, err := EncodeSMPClientHandshake(hs)
	if err != nil {
		t.Fatalf("encode v6: %v", err)
	}
	// Layout: Word16(6) | ShortString(zero KeyHash), no auth section.
	want := []byte{0x00, 0x06, 0x20}
	want = append(want, bytes.Repeat([]byte{0x00}, 32)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("v6 clientHello (auth must be omitted):\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeSMPClientHandshakeBelowMinVersion(t *testing.T) {
	hs := SMPClientHandshake{Version: 3}
	_, err := EncodeSMPClientHandshake(hs)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("below minimum")) {
		t.Fatalf("v3 should error, got %v", err)
	}
}

func TestDecodeSMPServerHandshakeV7NoAuth(t *testing.T) {
	sessID := []byte("session-bytes")
	// Layout: VersionRange(min=6, max=7) | ShortString(sessId) | (no auth, since absent)
	wire := []byte{0x00, 0x06, 0x00, 0x07, byte(len(sessID))}
	wire = append(wire, sessID...)

	hs, err := DecodeSMPServerHandshake(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hs.VersionRange.Min != VersionV6 || hs.VersionRange.Max != VersionV7 {
		t.Errorf("versions: got %+v want {6,7}", hs.VersionRange)
	}
	if !bytes.Equal(hs.SessionID, sessID) {
		t.Errorf("sessId: got %x want %x", hs.SessionID, sessID)
	}
	if hs.AuthPubKeyRaw != nil {
		t.Errorf("authPubKey: got %x want nil", hs.AuthPubKeyRaw)
	}
}

func TestDecodeSMPServerHandshakeV7WithAuth(t *testing.T) {
	sessID := []byte("sid")
	authBlob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	wire := []byte{0x00, 0x07, 0x00, 0x07, byte(len(sessID))}
	wire = append(wire, sessID...)
	wire = append(wire, authBlob...)

	hs, err := DecodeSMPServerHandshake(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(hs.AuthPubKeyRaw, authBlob) {
		t.Errorf("authPubKey blob: got %x want %x", hs.AuthPubKeyRaw, authBlob)
	}
}

func TestDecodeSMPServerHandshakeV6IgnoresTrailingBytes(t *testing.T) {
	sessID := []byte("sid")
	trailing := []byte{0xAA, 0xBB}
	// v6 → max=6, so we should NOT interpret trailing bytes as auth.
	wire := []byte{0x00, 0x06, 0x00, 0x06, byte(len(sessID))}
	wire = append(wire, sessID...)
	wire = append(wire, trailing...)

	hs, err := DecodeSMPServerHandshake(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hs.AuthPubKeyRaw != nil {
		t.Errorf("v6 authPubKey: got %x want nil (no auth field on v6)", hs.AuthPubKeyRaw)
	}
}

func TestDecodeSMPServerHandshakeTruncated(t *testing.T) {
	// VersionRange bytes only; sessionId missing.
	_, err := DecodeSMPServerHandshake([]byte{0x00, 0x06, 0x00, 0x07})
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: got %v want ErrTruncated", err)
	}
}

func TestNegotiateVersion(t *testing.T) {
	cases := []struct {
		name   string
		srvMin Version
		srvMax Version
		want   Version
		err    bool
	}{
		{"server-encompasses-client", 1, 99, MaxClientVersion, false},
		{"server-only-V6", VersionV6, VersionV6, VersionV6, false},
		{"server-only-V7", VersionV7, VersionV7, VersionV7, false},
		{"server-newer-than-client", VersionV18, VersionV18, 0, true},
		{"server-older-than-client", 1, 5, 0, true},
		{"overlap-cap-at-client-max", VersionV6, VersionV18, MaxClientVersion, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NegotiateVersion(VersionRange{Min: c.srvMin, Max: c.srvMax})
			if c.err {
				if err == nil {
					t.Fatalf("expected error, got version %d", got)
				}
				if !errors.Is(err, ErrIncompatibleVersion) {
					t.Fatalf("expected ErrIncompatibleVersion, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("negotiated version: got %d want %d", got, c.want)
			}
		})
	}
}
