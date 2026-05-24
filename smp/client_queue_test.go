package smp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// idsBody builds a server IDS response body (the bytes following "IDS ").
func idsBody(rcvID, sndID, dhKey []byte) []byte {
	body := []byte{byte(len(rcvID))}
	body = append(body, rcvID...)
	body = append(body, byte(len(sndID)))
	body = append(body, sndID...)
	body = append(body, byte(len(dhKey)))
	body = append(body, dhKey...)
	return body
}

func TestNewQueueDefaultSubMode(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)
	sndID := bytes.Repeat([]byte{0x22}, 24)
	dhKey := bytes.Repeat([]byte{0x33}, 32)

	signer := fakeSigner{sig: bytes.Repeat([]byte{0xAB}, 64)}
	doneCh := make(chan struct {
		ids IDSResponse
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := NewQueueReq{
			RcvAuthPubKeyDER: bytes.Repeat([]byte{0xAA}, 32),
			RcvDHPubKeyDER:   bytes.Repeat([]byte{0xBB}, 32),
			// SubscribeMode left at zero — should default to SubscribeManual
		}
		ids, err := c.NewQueue(ctx, signer, req)
		doneCh <- struct {
			ids IDSResponse
			err error
		}{ids, err}
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))

	// Server replies with IDS.
	idsCmd := append([]byte("IDS "), idsBody(rcvID, sndID, dhKey)...)
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, idsCmd)

	res := <-doneCh
	if res.err != nil {
		t.Fatalf("NewQueue: %v", res.err)
	}
	if !bytes.Equal(res.ids.RecipientID, rcvID) {
		t.Errorf("RecipientID: got %x want %x", res.ids.RecipientID, rcvID)
	}
	if !bytes.Equal(res.ids.SenderID, sndID) {
		t.Errorf("SenderID: got %x want %x", res.ids.SenderID, sndID)
	}
	if !bytes.Equal(res.ids.SrvDHPubKey, dhKey) {
		t.Errorf("SrvDHPubKey: got %x want %x", res.ids.SrvDHPubKey, dhKey)
	}

	// Verify the written NEW command had subscribeMode='C' (manual).
	ft.mu.Lock()
	last := ft.writes[len(ft.writes)-1]
	ft.mu.Unlock()
	txs, _ := DecodeBlock(VersionV7, []byte("test-session-id"), last)
	cmd := txs[0].Command
	if !bytes.HasPrefix(cmd, []byte("NEW ")) {
		t.Fatalf("cmd prefix: %q", cmd)
	}
	// Layout after "NEW ": shortStr(rcvAuth) + shortStr(rcvDH) + '0' + subMode
	// rcvAuth: 1 + 32 bytes; rcvDH: 1 + 32 bytes; basicAuth absent: 1 byte; subMode: 1 byte
	subModeIdx := 4 + (1 + 32) + (1 + 32) + 1
	if cmd[subModeIdx] != 'C' {
		t.Errorf("subscribeMode: got %q want 'C' (manual)", cmd[subModeIdx])
	}
}

func TestNewQueueRejectsSubscribeOnCreate(t *testing.T) {
	c, _ := newTestClient(t)
	req := NewQueueReq{
		RcvAuthPubKeyDER: []byte{0x01},
		RcvDHPubKeyDER:   []byte{0x02},
		SubscribeMode:    SubscribeOnCreate,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.NewQueue(ctx, fakeSigner{}, req)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("SubscribeOnCreate not yet supported")) {
		t.Fatalf("expected SubscribeOnCreate rejection, got %v", err)
	}
}

func TestNewQueueWrongResponse(t *testing.T) {
	c, ft := newTestClient(t)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := NewQueueReq{
			RcvAuthPubKeyDER: []byte{0x01},
			RcvDHPubKeyDER:   []byte{0x02},
			SubscribeMode:    SubscribeManual,
		}
		_, err := c.NewQueue(ctx, fakeSigner{}, req)
		doneCh <- err
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))

	err := <-doneCh
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("expected IDS")) {
		t.Fatalf("expected 'expected IDS', got %v", err)
	}
}

func TestSubscribeOK(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)

	doneCh := make(chan struct {
		ch  <-chan Message
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ch, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
		doneCh <- struct {
			ch  <-chan Message
			err error
		}{ch, err}
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))

	res := <-doneCh
	if res.err != nil {
		t.Fatalf("Subscribe: %v", res.err)
	}
	if res.ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	// Push a server-pushed MSG for this rcvID; should arrive on the channel.
	msgID := msgID24()
	msgBody := []byte("encrypted-payload")
	msgCmd := append([]byte("MSG "), byte(24))
	msgCmd = append(msgCmd, msgID...)
	msgCmd = append(msgCmd, msgBody...)
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), CorrID{}, rcvID, msgCmd)

	select {
	case m := <-res.ch:
		if !bytes.Equal(m.ID, msgID) {
			t.Errorf("MSG ID: got %x want %x", m.ID, msgID)
		}
		if !bytes.Equal(m.Body, msgBody) {
			t.Errorf("MSG body: got %q want %q", m.Body, msgBody)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive pushed MSG")
	}
}

func TestSubscribeFirstMsg(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)

	doneCh := make(chan struct {
		ch  <-chan Message
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ch, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
		doneCh <- struct {
			ch  <-chan Message
			err error
		}{ch, err}
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))

	// Server responds with MSG directly (first queued msg delivered inline).
	mid := msgID24()
	body := []byte("first-msg-body")
	msgCmd := append([]byte("MSG "), byte(24))
	msgCmd = append(msgCmd, mid...)
	msgCmd = append(msgCmd, body...)
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, msgCmd)

	res := <-doneCh
	if res.err != nil {
		t.Fatalf("Subscribe: %v", res.err)
	}
	// First message should already be in the channel buffer.
	select {
	case m := <-res.ch:
		if !bytes.Equal(m.ID, mid) {
			t.Errorf("first MSG ID: got %x want %x", m.ID, mid)
		}
		if !bytes.Equal(m.Body, body) {
			t.Errorf("first MSG body: got %q want %q", m.Body, body)
		}
	case <-time.After(time.Second):
		t.Fatal("first MSG not in channel")
	}
}

func TestSubscribeError(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
		doneCh <- err
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("ERR AUTH"))

	err := <-doneCh
	var em ErrMsg
	if !errors.As(err, &em) || em.Type != "AUTH" {
		t.Fatalf("Subscribe error: got %v, want ErrMsg{Type:AUTH}", err)
	}

	// Sub channel should have been unregistered.
	c.mu.Lock()
	_, exists := c.subs[string(rcvID)]
	c.mu.Unlock()
	if exists {
		t.Error("sub channel was not unregistered after error")
	}
}

func TestSubscribeAlreadySubscribed(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)

	// First Subscribe succeeds.
	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
		doneCh <- err
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))
	if err := <-doneCh; err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}

	// Second Subscribe for same rcvID immediately errors.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("already subscribed")) {
		t.Fatalf("second Subscribe: got %v want 'already subscribed'", err)
	}
}

func TestSubscribeEND(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)

	doneCh := make(chan struct {
		ch  <-chan Message
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ch, err := c.Subscribe(ctx, fakeSigner{}, rcvID)
		doneCh <- struct {
			ch  <-chan Message
			err error
		}{ch, err}
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))
	res := <-doneCh
	if res.err != nil {
		t.Fatalf("Subscribe: %v", res.err)
	}

	// Server pushes END.
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), CorrID{}, rcvID, []byte("END"))

	// Channel should close.
	select {
	case _, ok := <-res.ch:
		if ok {
			t.Fatal("channel returned a value after END; expected closed")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after END")
	}
}
