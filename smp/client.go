package smp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
)

// BlockTransport is the lower-level interface Client uses to exchange SMP
// transport blocks with a server. *Conn implements it directly; tests use a
// fake implementation.
type BlockTransport interface {
	ReadBlock(ctx context.Context) ([]byte, error)
	WriteBlock(ctx context.Context, payload []byte) error
	Close() error
}

// Client is a single connection to one SMP server, with the SMP handshake
// already complete (params populated).
//
// Concurrency model:
//   - One goroutine owns the receive side and dispatches incoming MSG/END
//     events to per-queue subscribers, and correlated responses to in-flight
//     command requests.
//   - Send-side methods are safe for concurrent callers; underlying
//     BlockTransport.WriteBlock is serialized via mu.
//   - All blocking methods accept a context.Context.
type Client struct {
	tx     BlockTransport
	params HandshakeParams

	mu       sync.Mutex
	closed   bool
	sentCmds map[CorrID]chan brokerResult
	subs     map[string]chan Message

	readerDone chan struct{}
}

// HandshakeParams is the negotiated SMP session state after both the TLS and
// SMP handshakes complete.
type HandshakeParams struct {
	Version Version
	// SessID is the tls-unique channel binding bytes from the underlying TLS
	// session. Included in the authorized bytes of every command.
	SessID SessionID
	// PeerAuthPubKey, when non-nil, is the server's X25519 public key used
	// (combined with each per-queue key) to authenticate commands in the v7+
	// deniable scheme.
	PeerAuthPubKey []byte
	// BlockSize is the negotiated transport block size. Always 16384 unless
	// the proxy variant negotiates something else (out of scope for slice 1).
	BlockSize int
}

type brokerResult struct {
	msg BrokerMsg
	err error
}

// NewClient wraps an already-handshook BlockTransport in a Client and starts
// the reader goroutine. Use Dial for the full TLS + SMP handshake path
// (currently unimplemented — see Dial doc).
func NewClient(tx BlockTransport, params HandshakeParams) *Client {
	c := &Client{
		tx:         tx,
		params:     params,
		sentCmds:   make(map[CorrID]chan brokerResult),
		subs:       make(map[string]chan Message),
		readerDone: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Dial opens a fresh connection, performs TLS + SMP handshake, and returns a
// Client ready for SMP commands.
//
// `sessionID` is the SMP session identifier — in production this is derived
// from the TLS handshake (Haskell uses RFC 5929 tls-unique; Go's TLS 1.3
// doesn't expose that, so callers must supply a value out-of-band or use
// ExportKeyingMaterial themselves). Whatever the caller passes is asserted
// to match what the server claims in its hello block.
//
// `ownAuthPriv` is the client's 32-byte X25519 private key whose public
// counterpart will be offered to the server for v7+ deniable command
// authentication. Pass nil for v<V7 or if the caller doesn't intend to
// authenticate commands (a fresh ephemeral key is generated for v7+ so the
// handshake completes either way; the caller-supplied key is preferred so
// the same key can be reused for later X25519AuthSigner construction).
//
// SPEC: simplexmq Transport.hs:792 (smpClientHandshake).
func Dial(ctx context.Context, addr string, expected KeyHash, sessionID SessionID, ownAuthPriv []byte, cfg TransportConfig) (*Client, error) {
	conn, err := DialTLS(ctx, addr, expected, cfg)
	if err != nil {
		return nil, err
	}
	params, err := runSMPClientHandshake(ctx, conn, expected, sessionID, ownAuthPriv)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewClient(conn, params), nil
}

// Close terminates the SMP session: closes the underlying transport, drains
// in-flight command channels with ErrClientClosed, closes subscriber channels,
// and joins the reader goroutine.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	for cid, ch := range c.sentCmds {
		ch <- brokerResult{err: ErrClientClosed}
		close(ch)
		delete(c.sentCmds, cid)
	}
	for rid, ch := range c.subs {
		close(ch)
		delete(c.subs, rid)
	}
	c.mu.Unlock()

	err := c.tx.Close()
	<-c.readerDone
	return err
}

// readLoop reads blocks from the transport and dispatches transmissions.
func (c *Client) readLoop() {
	defer close(c.readerDone)
	for {
		block, err := c.tx.ReadBlock(context.Background())
		if err != nil {
			c.handleReadError(err)
			return
		}
		txs, err := DecodeBlock(c.params.Version, c.params.SessID, block)
		if err != nil {
			// Slice 1: drop malformed blocks silently. Real impl should log.
			continue
		}
		for _, tx := range txs {
			c.dispatch(tx)
		}
	}
}

func (c *Client) handleReadError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	wrapped := fmt.Errorf("smp: read: %w", err)
	for cid, ch := range c.sentCmds {
		ch <- brokerResult{err: wrapped}
		close(ch)
		delete(c.sentCmds, cid)
	}
	for rid, ch := range c.subs {
		close(ch)
		delete(c.subs, rid)
	}
}

func (c *Client) dispatch(tx Transmission) {
	msg, err := DecodeBrokerMsg(c.params.Version, tx.Command)
	if err != nil {
		return // drop unparseable; slice 1 simplicity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if tx.CorrID == (CorrID{}) {
		// Server-pushed event: MSG (to subscriber) or END (close subscriber).
		key := string(tx.EntityID)
		ch, ok := c.subs[key]
		if !ok {
			return
		}
		switch m := msg.(type) {
		case MsgMsg:
			select {
			case ch <- m.Msg:
			default:
				// Subscriber buffer full — drop. Slice 1 simplicity;
				// real impl needs backpressure or a larger buffer.
			}
		case EndMsg:
			close(ch)
			delete(c.subs, key)
		}
		return
	}
	// Correlated response to one of our commands.
	if ch, ok := c.sentCmds[tx.CorrID]; ok {
		ch <- brokerResult{msg: msg}
		close(ch)
		delete(c.sentCmds, tx.CorrID)
	}
}

// send is the common request-response path: build transmission, write block,
// await response correlated by corrId.
func (c *Client) send(ctx context.Context, signKey RcvAuthKey, entityID EntityID, cmd Command) (BrokerMsg, error) {
	cmdBytes, err := EncodeCommand(c.params.Version, cmd)
	if err != nil {
		return nil, err
	}

	cid, err := newCorrID()
	if err != nil {
		return nil, fmt.Errorf("smp: corrId: %w", err)
	}

	tx := Transmission{
		CorrID:   cid,
		EntityID: entityID,
		Command:  cmdBytes,
	}

	// Compute auth bytes from a zero-Authorization transmission.
	_, authBytes, err := EncodeTransmission(c.params.Version, c.params.SessID, tx)
	if err != nil {
		return nil, err
	}
	if signKey != nil {
		sig, err := signKey.Authorize(authBytes, cid)
		if err != nil {
			return nil, fmt.Errorf("smp: authorize: %w", err)
		}
		tx.Authorization = sig
	}

	wireBytes, _, err := EncodeTransmission(c.params.Version, c.params.SessID, tx)
	if err != nil {
		return nil, err
	}
	block, err := EncodeBlock(wireBytes)
	if err != nil {
		return nil, err
	}

	respCh := make(chan brokerResult, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	c.sentCmds[cid] = respCh
	c.mu.Unlock()

	if err := c.tx.WriteBlock(ctx, block); err != nil {
		c.mu.Lock()
		delete(c.sentCmds, cid)
		c.mu.Unlock()
		return nil, fmt.Errorf("smp: write: %w", err)
	}

	select {
	case r := <-respCh:
		if r.err != nil {
			return nil, r.err
		}
		if e, ok := r.msg.(ErrMsg); ok {
			return nil, e
		}
		return r.msg, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.sentCmds, cid)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

func newCorrID() (CorrID, error) {
	var c CorrID
	_, err := io.ReadFull(rand.Reader, c[:])
	return c, err
}

// Ping sends PING and waits for PONG. SPEC: section "Keep-alive command".
func (c *Client) Ping(ctx context.Context) error {
	msg, err := c.send(ctx, nil, NoEntity, PingCmd{})
	if err != nil {
		return err
	}
	if _, ok := msg.(PongMsg); !ok {
		return fmt.Errorf("smp: PING expected PONG, got %T", msg)
	}
	return nil
}

// Send issues a SEND command to (sndID). `sigKey` may be nil for unauthorized
// sends before the queue is KEY/SKEY-secured. `body` is the pre-encoded
// smpEncMessage payload (not a raw application message).
//
// SPEC: section "Send message". Haskell ref: sendSMPMessage (Client.hs:1027).
func (c *Client) Send(ctx context.Context, sigKey SndAuthKey, sndID QueueID, flags MsgFlags, body []byte) error {
	msg, err := c.send(ctx, sigKey, sndID, SendCmd{Flags: flags, Body: body})
	if err != nil {
		return err
	}
	if _, ok := msg.(OKMsg); !ok {
		return fmt.Errorf("smp: SEND expected OK, got %T", msg)
	}
	return nil
}

// Ack acknowledges receipt of msgID on queue rcvID. Until Ack succeeds the
// server will not deliver the next message on this queue.
//
// SPEC: section "Acknowledge message delivery". Haskell ref: ackSMPMessage
// (Client.hs:1040).
func (c *Client) Ack(ctx context.Context, signKey RcvAuthKey, rcvID QueueID, msgID MsgID) error {
	msg, err := c.send(ctx, signKey, rcvID, AckCmd{MsgID: msgID})
	if err != nil {
		return err
	}
	if _, ok := msg.(OKMsg); !ok {
		return fmt.Errorf("smp: ACK expected OK, got %T", msg)
	}
	return nil
}

// NewQueue sends NEW and returns the server-assigned IDs + DH key.
//
// SubscribeMode handling:
//   - 0 (zero) → defaulted to SubscribeManual ('C').
//   - SubscribeManual → passed through.
//   - SubscribeOnCreate → rejected; auto-subscribe needs sub-buffering for
//     MSGs that may arrive before NewQueue returns and the caller registers a
//     subscriber. Call NewQueue with SubscribeManual, then Subscribe(rcvID).
//   - anything else → rejected.
//
// SPEC: section "Create queue command". Haskell ref: createSMPQueue (Client.hs:813).
func (c *Client) NewQueue(ctx context.Context, signKey RcvAuthKey, req NewQueueReq) (IDSResponse, error) {
	switch req.SubscribeMode {
	case 0:
		req.SubscribeMode = SubscribeManual
	case SubscribeManual:
		// ok
	case SubscribeOnCreate:
		return IDSResponse{}, errors.New("smp: NewQueue with SubscribeMode=SubscribeOnCreate not yet supported (sub-buffering race); use SubscribeManual and call Subscribe(rcvID) afterward")
	default:
		return IDSResponse{}, fmt.Errorf("smp: invalid SubscribeMode %#x", byte(req.SubscribeMode))
	}

	msg, err := c.send(ctx, signKey, NoEntity, NewCmd{Req: req})
	if err != nil {
		return IDSResponse{}, err
	}
	ids, ok := msg.(IDSMsg)
	if !ok {
		return IDSResponse{}, fmt.Errorf("smp: NEW expected IDS, got %T", msg)
	}
	return ids.IDS, nil
}

// Subscribe sends SUB on rcvID and returns a channel that the reader
// goroutine pushes delivered Messages into. The channel is closed when the
// server sends END (another connection took over) or the Client is closed.
//
// Behavior:
//   - Pre-registers subs[rcvID] before SUB is sent — eliminates the race
//     where a server-pushed MSG (corrId=0) for rcvID could arrive before the
//     channel exists.
//   - If SUB's response is MSG instead of OK (server delivers the first
//     queued message inline), pushes that MSG into the returned channel.
//   - On error or unexpected response, unregisters the sub and closes the
//     channel.
//
// SPEC: section "Subscribe to queue". Haskell ref: subscribeSMPQueue
// (Client.hs:833).
func (c *Client) Subscribe(ctx context.Context, signKey RcvAuthKey, rcvID QueueID) (<-chan Message, error) {
	key := string(rcvID)

	ch := make(chan Message, 32)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if _, exists := c.subs[key]; exists {
		c.mu.Unlock()
		return nil, fmt.Errorf("smp: already subscribed to queue %x", rcvID)
	}
	c.subs[key] = ch
	c.mu.Unlock()

	msg, err := c.send(ctx, signKey, rcvID, SubCmd{})
	if err != nil {
		c.mu.Lock()
		delete(c.subs, key)
		c.mu.Unlock()
		close(ch)
		return nil, err
	}

	switch m := msg.(type) {
	case OKMsg:
		// Subscription confirmed; subsequent MSGs come via the subs channel.
	case MsgMsg:
		// Server delivered first queued message inline as the SUB response.
		// Push it through the subscriber channel for the caller.
		ch <- m.Msg
	default:
		c.mu.Lock()
		delete(c.subs, key)
		c.mu.Unlock()
		close(ch)
		return nil, fmt.Errorf("smp: SUB expected OK or MSG, got %T", msg)
	}
	return ch, nil
}

// RcvAuthKey is the private half of a recipient's per-queue authentication
// key. Implementations encapsulate the signing/auth-tag operation so this
// package stays free of crypto dependencies.
//
// For Ed25519: Authorize signs `authorized` with Ed25519 (nonce ignored).
// For NaCl crypto_box (SMP v7+): Authorize computes the deniable
// authenticator: crypto_box(sha512(authorized); key=dh(queueKey, serverSessionKey); nonce).
type RcvAuthKey interface {
	Authorize(authorized []byte, nonce CorrID) ([]byte, error)
}

// SndAuthKey is the sender-side analogue of RcvAuthKey. May be nil for
// unauthorized sends to an unsecured queue.
type SndAuthKey = RcvAuthKey

// ErrClientClosed is returned from blocking methods when Client.Close was
// called or the underlying transport dropped.
var ErrClientClosed = errors.New("smp: client closed")
