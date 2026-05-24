package smp

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeTransport is a BlockTransport for unit-testing Client without TLS.
// Writes are captured; reads are served from a channel the test can feed.
type fakeTransport struct {
	mu       sync.Mutex
	writes   [][]byte
	reads    chan []byte
	closed   bool
	readErr  error
	writeErr error
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{reads: make(chan []byte, 8)}
}

func (f *fakeTransport) ReadBlock(ctx context.Context) ([]byte, error) {
	select {
	case b, ok := <-f.reads:
		if !ok {
			return nil, errors.New("transport closed")
		}
		f.mu.Lock()
		err := f.readErr
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeTransport) WriteBlock(ctx context.Context, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	f.writes = append(f.writes, cp)
	return nil
}

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.reads)
	}
	return nil
}

func (f *fakeTransport) injectBroker(t *testing.T, v Version, sessID SessionID, cid CorrID, entityID EntityID, cmd []byte) {
	t.Helper()
	tx := Transmission{
		CorrID:   cid,
		EntityID: entityID,
		Command:  cmd,
	}
	wire, _, err := EncodeTransmission(v, sessID, tx)
	if err != nil {
		t.Fatal(err)
	}
	block, err := EncodeBlock(wire)
	if err != nil {
		t.Fatal(err)
	}
	f.reads <- block
}

// extractWriteCorrID parses the corrId out of the most recent client write.
func (f *fakeTransport) extractWriteCorrID(t *testing.T, v Version, sessID SessionID) CorrID {
	t.Helper()
	f.mu.Lock()
	if len(f.writes) == 0 {
		f.mu.Unlock()
		t.Fatal("no writes captured")
	}
	last := f.writes[len(f.writes)-1]
	f.mu.Unlock()
	txs, err := DecodeBlock(v, sessID, last)
	if err != nil {
		t.Fatalf("decode write: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 tx in write, got %d", len(txs))
	}
	return txs[0].CorrID
}

func newTestClient(t *testing.T) (*Client, *fakeTransport) {
	t.Helper()
	ft := newFakeTransport()
	c := NewClient(ft, HandshakeParams{
		Version:   VersionV7,
		SessID:    []byte("test-session-id"),
		BlockSize: SMPBlockSize,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c, ft
}

func TestClientPing(t *testing.T) {
	c, ft := newTestClient(t)

	pongDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		pongDone <- c.Ping(ctx)
	}()

	// Wait for the write, extract corrId, inject PONG response.
	if !waitForWrite(ft, time.Second) {
		t.Fatal("client did not write PING")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("PONG"))

	if err := <-pongDone; err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestClientPingWrongResponse(t *testing.T) {
	c, ft := newTestClient(t)

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		errCh <- c.Ping(ctx)
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))

	err := <-errCh
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("expected PONG")) {
		t.Fatalf("Ping wrong response: got %v, want 'expected PONG'", err)
	}
}

func TestClientSendUnauthorized(t *testing.T) {
	c, ft := newTestClient(t)
	sndID := bytes.Repeat([]byte{0x77}, 24)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		doneCh <- c.Send(ctx, nil, sndID, MsgFlags{}, []byte("hello-body"))
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))

	if err := <-doneCh; err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify the captured write decodes to a SEND command with our body.
	ft.mu.Lock()
	last := ft.writes[len(ft.writes)-1]
	ft.mu.Unlock()
	txs, err := DecodeBlock(VersionV7, []byte("test-session-id"), last)
	if err != nil {
		t.Fatalf("decode write: %v", err)
	}
	tx := txs[0]
	if !bytes.Equal(tx.EntityID, sndID) {
		t.Errorf("entityId: got %x want %x", tx.EntityID, sndID)
	}
	if !bytes.HasPrefix(tx.Command, []byte("SEND F ")) {
		t.Errorf("command prefix: got %q want 'SEND F '", tx.Command[:7])
	}
	if !bytes.HasSuffix(tx.Command, []byte("hello-body")) {
		t.Errorf("command body: got %q", tx.Command)
	}
}

// fakeSigner returns a fixed signature regardless of input. Tests just need
// to verify Authorize is called and the bytes flow through.
type fakeSigner struct {
	sig []byte
}

func (f fakeSigner) Authorize(authorized []byte, nonce CorrID) ([]byte, error) {
	return f.sig, nil
}

func TestClientAck(t *testing.T) {
	c, ft := newTestClient(t)
	rcvID := bytes.Repeat([]byte{0x11}, 24)
	mid := msgID24()
	sig := bytes.Repeat([]byte{0xCC}, 64)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		doneCh <- c.Ack(ctx, fakeSigner{sig: sig}, rcvID, mid)
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("OK"))

	if err := <-doneCh; err != nil {
		t.Fatalf("Ack: %v", err)
	}

	ft.mu.Lock()
	last := ft.writes[len(ft.writes)-1]
	ft.mu.Unlock()
	txs, _ := DecodeBlock(VersionV7, []byte("test-session-id"), last)
	tx := txs[0]
	if !bytes.Equal(tx.Authorization, sig) {
		t.Errorf("Authorization: got %x want %x", tx.Authorization, sig)
	}
	if !bytes.HasPrefix(tx.Command, []byte("ACK ")) {
		t.Errorf("command prefix: got %q", tx.Command)
	}
}

func TestClientErrResponse(t *testing.T) {
	c, ft := newTestClient(t)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		doneCh <- c.Ping(ctx)
	}()
	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cid := ft.extractWriteCorrID(t, VersionV7, []byte("test-session-id"))
	ft.injectBroker(t, VersionV7, []byte("test-session-id"), cid, nil, []byte("ERR AUTH"))

	err := <-doneCh
	var em ErrMsg
	if !errors.As(err, &em) {
		t.Fatalf("expected ErrMsg, got %T %v", err, err)
	}
	if em.Type != "AUTH" {
		t.Errorf("ErrMsg.Type: got %q want AUTH", em.Type)
	}
}

func TestClientCloseDrainsPending(t *testing.T) {
	c, ft := newTestClient(t)

	doneCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		doneCh <- c.Ping(ctx)
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	// Close before any response — the pending Ping should fail with
	// ErrClientClosed.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := <-doneCh
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("pending Ping after close: got %v want ErrClientClosed", err)
	}
}

func TestClientCtxCancel(t *testing.T) {
	c, ft := newTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- c.Ping(ctx)
	}()

	if !waitForWrite(ft, time.Second) {
		t.Fatal("no write")
	}
	cancel()

	err := <-doneCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping with canceled ctx: got %v want Canceled", err)
	}
}

// waitForWrite polls fakeTransport.writes for non-empty within d.
func waitForWrite(f *fakeTransport, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.writes)
		f.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
