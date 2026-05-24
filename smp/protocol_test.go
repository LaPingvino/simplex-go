package smp

import (
	"bytes"
	"errors"
	"testing"
)

// Helper: known 24-byte msgId pattern.
func msgID24() []byte {
	b := make([]byte, 24)
	for i := range b {
		b[i] = byte(i + 1) // 0x01..0x18
	}
	return b
}

func TestEncodeSubCmd(t *testing.T) {
	got, err := EncodeCommand(VersionV7, SubCmd{})
	if err != nil {
		t.Fatalf("EncodeCommand SUB: %v", err)
	}
	if !bytes.Equal(got, []byte("SUB")) {
		t.Fatalf("SUB bytes: got %q want %q", got, "SUB")
	}
}

func TestEncodePingCmd(t *testing.T) {
	got, err := EncodeCommand(VersionV7, PingCmd{})
	if err != nil {
		t.Fatalf("EncodeCommand PING: %v", err)
	}
	if !bytes.Equal(got, []byte("PING")) {
		t.Fatalf("PING bytes: got %q want %q", got, "PING")
	}
}

func TestEncodeAckCmd(t *testing.T) {
	mid := msgID24()
	got, err := EncodeCommand(VersionV7, AckCmd{MsgID: mid})
	if err != nil {
		t.Fatalf("EncodeCommand ACK: %v", err)
	}
	want := append([]byte("ACK "), byte(24))
	want = append(want, mid...)
	if !bytes.Equal(got, want) {
		t.Fatalf("ACK bytes mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeSendCmd(t *testing.T) {
	body := []byte("payload-bytes")
	got, err := EncodeCommand(VersionV7, SendCmd{
		Flags: MsgFlags{Notification: true},
		Body:  body,
	})
	if err != nil {
		t.Fatalf("EncodeCommand SEND: %v", err)
	}
	want := []byte("SEND T ")
	want = append(want, body...)
	if !bytes.Equal(got, want) {
		t.Fatalf("SEND bytes:\n  got  %q\n  want %q", got, want)
	}

	// Notification=false uses 'F'.
	got, err = EncodeCommand(VersionV7, SendCmd{
		Flags: MsgFlags{Notification: false},
		Body:  body,
	})
	if err != nil {
		t.Fatalf("EncodeCommand SEND(notif=false): %v", err)
	}
	if got[5] != 'F' {
		t.Fatalf("SEND notification false byte: got %q want 'F'", got[5])
	}
}

func TestEncodeNewCmdV7NoBasicAuth(t *testing.T) {
	// Realistic-ish stand-in keys: 32-byte placeholders (X.509 form would be
	// larger but the encoder doesn't care about the contents).
	rcvAuth := bytes.Repeat([]byte{0xAA}, 32)
	rcvDH := bytes.Repeat([]byte{0xBB}, 32)
	req := NewQueueReq{
		RcvAuthPubKeyDER: rcvAuth,
		RcvDHPubKeyDER:   rcvDH,
		BasicAuth:        "",
		SubscribeMode:    SubscribeOnCreate,
	}
	got, err := EncodeCommand(VersionV7, NewCmd{Req: req})
	if err != nil {
		t.Fatalf("EncodeCommand NEW: %v", err)
	}

	want := []byte("NEW ")
	want = append(want, byte(32))
	want = append(want, rcvAuth...)
	want = append(want, byte(32))
	want = append(want, rcvDH...)
	want = append(want, '0') // basicAuth absent
	want = append(want, 'S') // subscribeMode
	// no sndSecure on v7

	if !bytes.Equal(got, want) {
		t.Fatalf("NEW v7 bytes mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeNewCmdV9WithBasicAuthAndSndSecure(t *testing.T) {
	rcvAuth := bytes.Repeat([]byte{0xAA}, 32)
	rcvDH := bytes.Repeat([]byte{0xBB}, 32)
	req := NewQueueReq{
		RcvAuthPubKeyDER: rcvAuth,
		RcvDHPubKeyDER:   rcvDH,
		BasicAuth:        "hunter2",
		SubscribeMode:    SubscribeManual,
		SenderCanSecure:  true,
	}
	got, err := EncodeCommand(VersionV9, NewCmd{Req: req})
	if err != nil {
		t.Fatalf("EncodeCommand NEW v9: %v", err)
	}

	want := []byte("NEW ")
	want = append(want, byte(32))
	want = append(want, rcvAuth...)
	want = append(want, byte(32))
	want = append(want, rcvDH...)
	want = append(want, '1', byte(len("hunter2")))
	want = append(want, []byte("hunter2")...)
	want = append(want, 'C') // subscribeMode = manual
	want = append(want, 'T') // sndSecure
	if !bytes.Equal(got, want) {
		t.Fatalf("NEW v9 bytes:\n  got  %x\n  want %x", got, want)
	}
}

func TestEncodeNewCmdSubModeDefaultsToS(t *testing.T) {
	req := NewQueueReq{
		RcvAuthPubKeyDER: []byte{0x01},
		RcvDHPubKeyDER:   []byte{0x02},
	}
	got, err := EncodeCommand(VersionV7, NewCmd{Req: req})
	if err != nil {
		t.Fatalf("EncodeCommand NEW: %v", err)
	}
	// SubscribeMode was zero — encoder should default to 'S'.
	// Layout: "NEW " + 0x01 0x01 + 0x01 0x02 + '0' + 'S'
	want := []byte{'N', 'E', 'W', ' ', 0x01, 0x01, 0x01, 0x02, '0', 'S'}
	if !bytes.Equal(got, want) {
		t.Fatalf("NEW default subMode:\n  got  %x\n  want %x", got, want)
	}
}

type unknownCmd struct{}

func (unknownCmd) smpCommand() {}

func TestEncodeUnknownCommand(t *testing.T) {
	_, err := EncodeCommand(VersionV7, unknownCmd{})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unknown command type")) {
		t.Fatalf("unknown cmd: got err=%v, want 'unknown command type'", err)
	}
}

func TestDecodeOK(t *testing.T) {
	m, err := DecodeBrokerMsg(VersionV7, []byte("OK"))
	if err != nil {
		t.Fatalf("DecodeBrokerMsg OK: %v", err)
	}
	if _, ok := m.(OKMsg); !ok {
		t.Fatalf("DecodeBrokerMsg OK: got %T want OKMsg", m)
	}
}

func TestDecodePong(t *testing.T) {
	m, err := DecodeBrokerMsg(VersionV7, []byte("PONG"))
	if err != nil {
		t.Fatalf("DecodeBrokerMsg PONG: %v", err)
	}
	if _, ok := m.(PongMsg); !ok {
		t.Fatalf("DecodeBrokerMsg PONG: got %T want PongMsg", m)
	}
}

func TestDecodeEnd(t *testing.T) {
	m, err := DecodeBrokerMsg(VersionV7, []byte("END"))
	if err != nil {
		t.Fatalf("DecodeBrokerMsg END: %v", err)
	}
	if _, ok := m.(EndMsg); !ok {
		t.Fatalf("DecodeBrokerMsg END: got %T want EndMsg", m)
	}
}

func TestDecodeERR(t *testing.T) {
	cases := []struct {
		wire           string
		wantType, wantDetail string
	}{
		{"ERR AUTH", "AUTH", ""},
		{"ERR LARGE_MSG limit reached", "LARGE_MSG", "limit reached"},
		{"ERR CMD NO_AUTH", "CMD", "NO_AUTH"},
	}
	for _, tc := range cases {
		m, err := DecodeBrokerMsg(VersionV7, []byte(tc.wire))
		if err != nil {
			t.Fatalf("DecodeBrokerMsg %q: %v", tc.wire, err)
		}
		em, ok := m.(ErrMsg)
		if !ok {
			t.Fatalf("DecodeBrokerMsg %q: got %T want ErrMsg", tc.wire, m)
		}
		if em.Type != tc.wantType || em.Detail != tc.wantDetail {
			t.Fatalf("DecodeBrokerMsg %q: got %+v want {Type:%q Detail:%q}",
				tc.wire, em, tc.wantType, tc.wantDetail)
		}
	}
}

func TestDecodeIDSV7(t *testing.T) {
	rcvID := bytes.Repeat([]byte{0x11}, 24)
	sndID := bytes.Repeat([]byte{0x22}, 24)
	dhKey := bytes.Repeat([]byte{0x33}, 32)

	wire := []byte("IDS ")
	wire = append(wire, byte(24))
	wire = append(wire, rcvID...)
	wire = append(wire, byte(24))
	wire = append(wire, sndID...)
	wire = append(wire, byte(32))
	wire = append(wire, dhKey...)

	m, err := DecodeBrokerMsg(VersionV7, wire)
	if err != nil {
		t.Fatalf("DecodeBrokerMsg IDS v7: %v", err)
	}
	ids, ok := m.(IDSMsg)
	if !ok {
		t.Fatalf("DecodeBrokerMsg IDS: got %T want IDSMsg", m)
	}
	if !bytes.Equal(ids.IDS.RecipientID, rcvID) {
		t.Errorf("RecipientID: got %x want %x", ids.IDS.RecipientID, rcvID)
	}
	if !bytes.Equal(ids.IDS.SenderID, sndID) {
		t.Errorf("SenderID: got %x want %x", ids.IDS.SenderID, sndID)
	}
	if !bytes.Equal(ids.IDS.SrvDHPubKey, dhKey) {
		t.Errorf("SrvDHPubKey: got %x want %x", ids.IDS.SrvDHPubKey, dhKey)
	}
	if ids.IDS.SndCanSecure {
		t.Errorf("SndCanSecure on v7: got true, want false (field absent in v7)")
	}
}

func TestDecodeIDSV9(t *testing.T) {
	wire := []byte("IDS ")
	wire = append(wire, byte(1), 0xAA) // recipientId
	wire = append(wire, byte(1), 0xBB) // senderId
	wire = append(wire, byte(1), 0xCC) // dhKey
	wire = append(wire, 'T')           // sndCanSecure

	m, err := DecodeBrokerMsg(VersionV9, wire)
	if err != nil {
		t.Fatalf("DecodeBrokerMsg IDS v9: %v", err)
	}
	ids := m.(IDSMsg).IDS
	if !ids.SndCanSecure {
		t.Errorf("SndCanSecure on v9: got false want true")
	}
}

func TestDecodeMSG(t *testing.T) {
	mid := msgID24()
	body := []byte("encrypted-body-placeholder")

	wire := []byte("MSG ")
	wire = append(wire, byte(24))
	wire = append(wire, mid...)
	wire = append(wire, body...)

	m, err := DecodeBrokerMsg(VersionV7, wire)
	if err != nil {
		t.Fatalf("DecodeBrokerMsg MSG: %v", err)
	}
	mm, ok := m.(MsgMsg)
	if !ok {
		t.Fatalf("DecodeBrokerMsg MSG: got %T want MsgMsg", m)
	}
	if !bytes.Equal(mm.Msg.ID, mid) {
		t.Errorf("MSG ID: got %x want %x", mm.Msg.ID, mid)
	}
	if !bytes.Equal(mm.Msg.Body, body) {
		t.Errorf("MSG Body: got %q want %q", mm.Msg.Body, body)
	}
}

func TestDecodeEmpty(t *testing.T) {
	_, err := DecodeBrokerMsg(VersionV7, []byte{})
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("empty: got %v want ErrBadEncoding", err)
	}
}

func TestDecodeUnknownPrefix(t *testing.T) {
	_, err := DecodeBrokerMsg(VersionV7, []byte("FROBNICATE"))
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("unknown prefix: got %v want ErrBadEncoding", err)
	}
}
