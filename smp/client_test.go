package smp

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestRoundTrip is the first vertical-slice end-to-end test. It is skipped
// unless both SMP_SERVER_ADDR (host:port) and SMP_SERVER_FINGERPRINT (hex
// SHA-256 of the offline cert, no separators) are set in the environment.
//
// The flow it exercises (and the proof that the wire bytes are right):
//
//  1. Dial(): TLS handshake with fingerprint pinning + SMP handshake.
//  2. NewQueue(): NEW -> IDS.
//  3. Subscribe(): SUB -> OK (auto-subscribed by NEW, but this exercises
//     the path nonetheless; alternately use NewQueueReq.SubscribeMode =
//     SubscribeManual to require a real SUB).
//  4. Send(): SEND <one byte> -> OK from the server's perspective.
//  5. Receive on the subscription channel -> MSG with our byte inside.
//  6. Ack(): ACK msgId -> OK.
//
// All steps panic("not implemented") today; this test just wires them up so
// that flipping the panics to real bodies one at a time is straightforward.
func TestRoundTrip(t *testing.T) {
	addr := os.Getenv("SMP_SERVER_ADDR")
	if addr == "" {
		t.Skip("SMP_SERVER_ADDR not set; skipping integration test")
	}
	fpHex := os.Getenv("SMP_SERVER_FINGERPRINT")
	if fpHex == "" {
		t.Skip("SMP_SERVER_FINGERPRINT not set; skipping integration test")
	}
	fpBytes, err := hex.DecodeString(fpHex)
	if err != nil {
		t.Fatalf("parse SMP_SERVER_FINGERPRINT: %v", err)
	}
	if len(fpBytes) != 32 {
		t.Fatalf("SMP_SERVER_FINGERPRINT must be 32 bytes (SHA-256), got %d", len(fpBytes))
	}
	var fp KeyHash
	copy(fp[:], fpBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := TransportConfig{DialTimeout: 10 * time.Second, IOTimeout: 5 * time.Second}
	// SMP_SESSION_ID is a placeholder until we wire TLS-derived session
	// identifier extraction (see runSMPClientHandshake docs).
	sessID := []byte(os.Getenv("SMP_SESSION_ID"))
	client, err := Dial(ctx, addr, fp, sessID, nil, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Caller-supplied keys — for the test these will be generated with
	// crypto/ed25519 (NEW signing) and crypto/ecdh X25519 (per-queue body
	// encryption). We hold off on writing the test crypto until the
	// Authorize interface is implemented; for now placeholders make the
	// intent visible.
	var rcvSign RcvAuthKey  // = ed25519Adapter(privKey)
	var rcvDHPubDER []byte  // = x509.MarshalPKIXPublicKey(dhPub)
	var rcvAuthPubDER []byte // = x509.MarshalPKIXPublicKey(signPub)

	req := NewQueueReq{
		RcvAuthPubKeyDER: rcvAuthPubDER,
		RcvDHPubKeyDER:   rcvDHPubDER,
		SubscribeMode:    SubscribeOnCreate,
	}
	ids, err := client.NewQueue(ctx, rcvSign, req)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	if len(ids.RecipientID) == 0 || len(ids.SenderID) == 0 {
		t.Fatalf("NewQueue returned empty IDs: %+v", ids)
	}

	// Auto-subscribed by NEW(S), but Subscribe() should also be safe.
	msgs, err := client.Subscribe(ctx, rcvSign, ids.RecipientID)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Unauthorized SEND of a single byte. Per SPEC this is valid until the
	// queue is secured with KEY/SKEY.
	payload := []byte{0x42}
	if err := client.Send(ctx, nil, ids.SenderID, MsgFlags{}, encodeSmpEnvelope(payload)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var got Message
	select {
	case got = <-msgs:
	case <-ctx.Done():
		t.Fatalf("waiting for MSG: %v", ctx.Err())
	}

	body := decodeSmpEnvelope(got.Body)
	if len(body) != 1 || body[0] != 0x42 {
		t.Fatalf("MSG body mismatch: got %x, want 42", body)
	}

	if err := client.Ack(ctx, rcvSign, ids.RecipientID, got.ID); err != nil {
		t.Fatalf("Ack: %v", err)
	}
}

// encodeSmpEnvelope wraps `payload` into the smpEncMessage / smpClientMessage
// structure required by SEND. For the first slice we are not e2e-encrypting,
// so this is currently a placeholder that returns the payload as-is.
//
// SPEC: smpClientMessage = emptyHeader clientMsgBody; emptyHeader = "_".
// Full layering (smpPubHeader + nonce + auth-tag + padded body) is in scope
// for vertical slice 2.
func encodeSmpEnvelope(payload []byte) []byte {
	_ = payload
	panic("not implemented")
}

// decodeSmpEnvelope reverses encodeSmpEnvelope on a received MSG body.
func decodeSmpEnvelope(body []byte) []byte {
	_ = body
	panic("not implemented")
}
