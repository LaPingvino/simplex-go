package smp

import (
	"context"
	"errors"
	"sync"
)

// Client is a single TLS-pinned, handshake-completed connection to one SMP
// server. It is the entry point for all five vertical-slice commands:
// NewQueue, Subscribe, Send, Receive, Ack.
//
// Concurrency model (subject to open-question #1 in the report):
//   - One goroutine owns the receive side and dispatches incoming MSG / END
//     events to per-queue subscribers.
//   - Send-side methods are safe for concurrent callers; the underlying TLS
//     writer is serialized with a mutex.
//   - All blocking methods accept a context.Context.
type Client struct {
	conn   *Conn
	params HandshakeParams

	mu  sync.Mutex // serializes block writes
	// sentCmds maps CorrID -> chan<- BrokerMsg for in-flight commands
	// awaiting a server response. The reader goroutine fills these.
	sentCmds map[CorrID]chan BrokerMsg

	// subs maps RecipientID -> channel that the reader pushes MSG events to.
	// Closed when the queue is unsubscribed or the connection drops.
	subs map[string]chan Message
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

// Dial opens a fresh connection to the SMP server at addr, runs the TLS
// handshake (pinning the offline cert fingerprint to `expected`), and then
// performs the SMP server/client handshake.
//
// On success the returned Client has a background reader goroutine running.
//
// SPEC ref: Haskell `smpClientHandshake` (Transport.hs:792). Order of
// operations:
//  1. TLS handshake with ALPN "smp/1".
//  2. Read paddedServerHello block.
//  3. Validate `serverIdentity` fingerprint inside the cert chain returned in
//     paddedServerHello.authPubKey.
//  4. Choose the max of (our version range ∩ server's range).
//  5. Write paddedClientHello with our chosen version.
//  6. Compute thAuth (sessSecret) when v >= 7.
//  7. Spawn the reader goroutine.
func Dial(ctx context.Context, addr string, expected KeyHash, cfg TransportConfig) (*Client, error) {
	_ = ctx
	_ = addr
	_ = expected
	_ = cfg
	panic("not implemented")
}

// Close terminates the SMP session, closes the underlying TLS connection,
// drains in-flight command channels with ErrClientClosed, and joins the
// reader goroutine.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	panic("not implemented")
}

// NewQueue sends a NEW command and returns the server-assigned (RecipientID,
// SenderID) plus the server's DH public key for the per-queue body-encryption
// secret.
//
// `req.RcvAuthPubKeyDER` must be the X.509 SPKI form of the public key whose
// private counterpart will sign all subsequent recipient commands on this
// queue. `req.RcvDHPubKeyDER` is the X25519 DH public key.
//
// Caller is responsible for generating both keypairs and stashing the
// private halves; this package does not own key material.
//
// SPEC: section "Create queue command".
// Haskell ref: createSMPQueue (Client.hs:813).
func (c *Client) NewQueue(ctx context.Context, signKey RcvAuthKey, req NewQueueReq) (IDSResponse, error) {
	_ = ctx
	_ = signKey
	_ = req
	panic("not implemented")
}

// Subscribe issues a SUB command on (rcvID) and returns a channel that the
// reader goroutine will push delivered Messages into. The channel is closed
// when an END is received (another connection has taken over) or the Client
// is closed.
//
// The caller must Ack each message before the next will be delivered (SPEC:
// "to receive the following message the recipient must acknowledge the
// reception of the message").
//
// SPEC: section "Subscribe to queue".
// Haskell ref: subscribeSMPQueue (Client.hs:833).
func (c *Client) Subscribe(ctx context.Context, signKey RcvAuthKey, rcvID QueueID) (<-chan Message, error) {
	_ = ctx
	_ = signKey
	_ = rcvID
	panic("not implemented")
}

// Send issues a SEND command to (sndID). For the first vertical-slice test we
// send an unauthorized empty-header body (the spec allows unauthorized SEND
// before a queue is secured). `body` is the pre-encoded smpEncMessage
// payload, NOT a raw application message.
//
// `sigKey` may be nil for unauthorized sends (queue not yet KEY'd). Otherwise
// it is the sender's private key whose public counterpart was registered with
// KEY / SKEY.
//
// SPEC: section "Send message".
// Haskell ref: sendSMPMessage (Client.hs:1027).
func (c *Client) Send(ctx context.Context, sigKey SndAuthKey, sndID QueueID, flags MsgFlags, body []byte) error {
	_ = ctx
	_ = sigKey
	_ = sndID
	_ = flags
	_ = body
	panic("not implemented")
}

// Ack acknowledges receipt of msgID on queue rcvID. Until Ack succeeds, the
// server will not deliver the next message on this queue.
//
// SPEC: section "Acknowledge message delivery".
// Haskell ref: ackSMPMessage (Client.hs:1040).
func (c *Client) Ack(ctx context.Context, signKey RcvAuthKey, rcvID QueueID, msgID MsgID) error {
	_ = ctx
	_ = signKey
	_ = rcvID
	_ = msgID
	panic("not implemented")
}

// Ping sends PING and waits for PONG. Useful for liveness checks and traffic
// padding (SPEC: "to keep the transport connection alive and to generate
// noise traffic the clients should use ping command").
func (c *Client) Ping(ctx context.Context) error {
	_ = ctx
	panic("not implemented")
}

// RcvAuthKey is the private half of a recipient's per-queue authentication
// key. The concrete representation depends on the auth scheme chosen at
// queue creation time:
//   - Ed25519: 32-byte ed25519.PrivateKey seed (crypto/ed25519).
//   - X25519 (NaCl crypto_box): 32-byte Curve25519 private key.
//
// The opaque interface keeps the smp package from depending on a specific
// crypto library. Callers wrap their key in a small adapter.
type RcvAuthKey interface {
	// Authorize is called per-transmission to either sign (Ed25519) or
	// compute a crypto_box authenticator (X25519) over `authorized`.
	// `nonce` is the 24-byte CorrID — used as the NaCl nonce in the X25519
	// case, ignored for Ed25519.
	Authorize(authorized []byte, nonce CorrID) ([]byte, error)
}

// SndAuthKey is the sender-side analogue of RcvAuthKey. May be nil for
// unauthorized sends to an unsecured queue.
type SndAuthKey = RcvAuthKey

// ErrClientClosed is returned from blocking methods when Client.Close was
// called or the underlying transport dropped.
var ErrClientClosed = errors.New("smp: client closed")

// ErrTimeout is a sentinel used when waiting for a server response exceeds
// the context deadline.
var ErrTimeout = errors.New("smp: server response timed out")
