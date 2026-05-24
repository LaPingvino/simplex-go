package smp

import (
	"bytes"
	"errors"
	"testing"
)

func freshCorrID() CorrID {
	var c CorrID
	for i := range c {
		c[i] = byte(i + 0xA0)
	}
	return c
}

func TestEncodeTransmissionV7AuthAndWire(t *testing.T) {
	sessID := []byte("session-bytes-here")
	cid := freshCorrID()
	cmd, err := EncodeCommand(VersionV7, SubCmd{})
	if err != nil {
		t.Fatal(err)
	}
	tx := Transmission{
		CorrID:        cid,
		EntityID:      bytes.Repeat([]byte{0x33}, 16),
		Command:       cmd,
		Authorization: bytes.Repeat([]byte{0xCC}, 64), // pretend-Ed25519 sig
	}

	wire, auth, err := EncodeTransmission(VersionV7, sessID, tx)
	if err != nil {
		t.Fatalf("EncodeTransmission v7: %v", err)
	}

	// authBytes = ShortString(sessID) + 0x18+cid + ShortString(entityID) + cmd
	wantAuth := []byte{byte(len(sessID))}
	wantAuth = append(wantAuth, sessID...)
	wantAuth = append(wantAuth, 0x18)
	wantAuth = append(wantAuth, cid[:]...)
	wantAuth = append(wantAuth, byte(16))
	wantAuth = append(wantAuth, tx.EntityID...)
	wantAuth = append(wantAuth, cmd...)
	if !bytes.Equal(auth, wantAuth) {
		t.Fatalf("authBytes v7:\n  got  %x\n  want %x", auth, wantAuth)
	}

	// wireBytes v7 = ShortString(authorization) + (NO sessID) + 0x18+cid + ShortString(entityID) + cmd
	wantWire := []byte{byte(len(tx.Authorization))}
	wantWire = append(wantWire, tx.Authorization...)
	wantWire = append(wantWire, 0x18)
	wantWire = append(wantWire, cid[:]...)
	wantWire = append(wantWire, byte(16))
	wantWire = append(wantWire, tx.EntityID...)
	wantWire = append(wantWire, cmd...)
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wireBytes v7:\n  got  %x\n  want %x", wire, wantWire)
	}
}

func TestEncodeTransmissionV6IncludesSessIDOnWire(t *testing.T) {
	sessID := []byte("v6-sess")
	cid := freshCorrID()
	cmd, _ := EncodeCommand(VersionV6, SubCmd{})
	tx := Transmission{
		CorrID:        cid,
		EntityID:      []byte{0xAB, 0xCD},
		Command:       cmd,
		Authorization: bytes.Repeat([]byte{0xEE}, 32),
	}

	wire, _, err := EncodeTransmission(VersionV6, sessID, tx)
	if err != nil {
		t.Fatalf("EncodeTransmission v6: %v", err)
	}

	// v6 wire = ShortString(auth) + ShortString(sessID) + 0x18+cid + ShortString(entityID) + cmd
	wantWire := []byte{byte(len(tx.Authorization))}
	wantWire = append(wantWire, tx.Authorization...)
	wantWire = append(wantWire, byte(len(sessID)))
	wantWire = append(wantWire, sessID...)
	wantWire = append(wantWire, 0x18)
	wantWire = append(wantWire, cid[:]...)
	wantWire = append(wantWire, byte(2))
	wantWire = append(wantWire, tx.EntityID...)
	wantWire = append(wantWire, cmd...)
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wireBytes v6 (must include sessID):\n  got  %x\n  want %x", wire, wantWire)
	}
}

func TestEncodeCorrIDZeroAndNonZero(t *testing.T) {
	// Zero CorrID -> 0x00.
	e := NewEncoder()
	encodeCorrID(e, CorrID{})
	if !bytes.Equal(e.Bytes(), []byte{0x00}) {
		t.Fatalf("zero corrId: got %x want 00", e.Bytes())
	}
	// Non-zero CorrID -> 0x18 + 24 bytes.
	cid := freshCorrID()
	e = NewEncoder()
	encodeCorrID(e, cid)
	if len(e.Bytes()) != 25 || e.Bytes()[0] != 0x18 {
		t.Fatalf("non-zero corrId: got %x", e.Bytes())
	}
	if !bytes.Equal(e.Bytes()[1:], cid[:]) {
		t.Fatalf("non-zero corrId body mismatch")
	}
}

func TestDecodeCorrIDBadTag(t *testing.T) {
	_, err := decodeCorrID(NewDecoder([]byte{0x05, 0x01, 0x02}))
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("bad corrId tag: got %v want ErrBadEncoding", err)
	}
}

func TestEncodeBlockSingle(t *testing.T) {
	t1 := []byte("first")
	block, err := EncodeBlock(t1)
	if err != nil {
		t.Fatalf("EncodeBlock: %v", err)
	}
	want := []byte{0x01, 0x00, 0x05}
	want = append(want, t1...)
	if !bytes.Equal(block, want) {
		t.Fatalf("EncodeBlock single:\n  got  %x\n  want %x", block, want)
	}
}

func TestEncodeBlockMultiple(t *testing.T) {
	t1 := []byte("a")
	t2 := []byte("bb")
	t3 := []byte("ccc")
	block, err := EncodeBlock(t1, t2, t3)
	if err != nil {
		t.Fatalf("EncodeBlock: %v", err)
	}
	want := []byte{0x03, 0x00, 0x01}
	want = append(want, t1...)
	want = append(want, 0x00, 0x02)
	want = append(want, t2...)
	want = append(want, 0x00, 0x03)
	want = append(want, t3...)
	if !bytes.Equal(block, want) {
		t.Fatalf("EncodeBlock multi:\n  got  %x\n  want %x", block, want)
	}
}

func TestEncodeBlockTooManyTransmissions(t *testing.T) {
	txs := make([][]byte, 256)
	for i := range txs {
		txs[i] = []byte{0}
	}
	_, err := EncodeBlock(txs...)
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("EncodeBlock 256 tx: got %v want ErrBadEncoding", err)
	}
}

func TestTransmissionRoundTripV7(t *testing.T) {
	sessID := []byte("session-7")
	cid := freshCorrID()
	cmd, _ := EncodeCommand(VersionV7, AckCmd{MsgID: msgID24()})
	tx := Transmission{
		CorrID:        cid,
		EntityID:      bytes.Repeat([]byte{0x55}, 24),
		Command:       cmd,
		Authorization: bytes.Repeat([]byte{0xAA}, 64),
	}

	wire, _, err := EncodeTransmission(VersionV7, sessID, tx)
	if err != nil {
		t.Fatal(err)
	}
	block, err := EncodeBlock(wire)
	if err != nil {
		t.Fatal(err)
	}

	out, err := DecodeBlock(VersionV7, sessID, block)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("DecodeBlock: got %d tx want 1", len(out))
	}
	g := out[0]
	if g.CorrID != cid {
		t.Errorf("CorrID: got %x want %x", g.CorrID, cid)
	}
	if !bytes.Equal(g.EntityID, tx.EntityID) {
		t.Errorf("EntityID: got %x want %x", g.EntityID, tx.EntityID)
	}
	if !bytes.Equal(g.Command, tx.Command) {
		t.Errorf("Command: got %x want %x", g.Command, tx.Command)
	}
	if !bytes.Equal(g.Authorization, tx.Authorization) {
		t.Errorf("Authorization: got %x want %x", g.Authorization, tx.Authorization)
	}
}

func TestTransmissionRoundTripV6(t *testing.T) {
	sessID := []byte("session-v6")
	cid := freshCorrID()
	cmd, _ := EncodeCommand(VersionV6, SubCmd{})
	tx := Transmission{
		CorrID:        cid,
		EntityID:      []byte{0x01, 0x02, 0x03},
		Command:       cmd,
		Authorization: []byte{0xEE},
	}

	wire, _, err := EncodeTransmission(VersionV6, sessID, tx)
	if err != nil {
		t.Fatal(err)
	}
	block, err := EncodeBlock(wire)
	if err != nil {
		t.Fatal(err)
	}

	out, err := DecodeBlock(VersionV6, sessID, block)
	if err != nil {
		t.Fatalf("DecodeBlock v6: %v", err)
	}
	if len(out) != 1 || out[0].CorrID != cid {
		t.Fatalf("DecodeBlock v6: bad result %+v", out)
	}
}

func TestDecodeBlockSessIDMismatchV6(t *testing.T) {
	sessID := []byte("orig-sess")
	cid := freshCorrID()
	cmd, _ := EncodeCommand(VersionV6, SubCmd{})
	tx := Transmission{CorrID: cid, EntityID: []byte{0x01}, Command: cmd, Authorization: []byte{0xEE}}
	wire, _, _ := EncodeTransmission(VersionV6, sessID, tx)
	block, _ := EncodeBlock(wire)

	_, err := DecodeBlock(VersionV6, []byte("wrong-sess"), block)
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("sessId mismatch on v6: got %v want ErrBadEncoding", err)
	}
}

func TestDecodeBlockTruncated(t *testing.T) {
	// Claim 1 transmission of length 100, supply only 3 bytes of body.
	block := []byte{0x01, 0x00, 0x64, 0xAA, 0xBB, 0xCC}
	_, err := DecodeBlock(VersionV7, nil, block)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated block: got %v want ErrTruncated wrapped", err)
	}
}

func TestDecodeBlockEmpty(t *testing.T) {
	_, err := DecodeBlock(VersionV7, nil, []byte{})
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty block: got %v want ErrTruncated", err)
	}
}
