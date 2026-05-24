package smp

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

// Version identifies an SMP protocol version (a single 16-bit word in the
// handshake; see SPEC "smpVersion = 2*2OCTET").
//
// Versions of interest for the first vertical slice:
//   - v6  — minimum supported by reference server; signature-only auth, batch on.
//   - v7  — adds NaCl crypto_box-based deniable authenticator; implies sessId.
//   - v9  — adds SKEY (sender secures queue) — out of scope for first slice.
//   - v11 — adds transport-block encryption layer — out of scope for first slice.
//   - v18 — current at time of writing (Haskell `currentClientSMPRelayVersion`).
type Version uint16

const (
	VersionV6  Version = 6
	VersionV7  Version = 7
	VersionV9  Version = 9
	VersionV11 Version = 11
	VersionV18 Version = 18

	// MinClientVersion is the minimum SMP version this Go client will offer in
	// its handshake. Per SPEC and Haskell `minClientSMPRelayVersion`, this is 6.
	MinClientVersion = VersionV6

	// MaxClientVersion is the maximum SMP version this Go client will offer.
	// Pin to v7 initially — that is the simplest version that still works with
	// modern reference servers (and matches the auth scheme we are going to
	// implement first). Bump to v9+ once SKEY / proxy / transport-encryption
	// features are added.
	MaxClientVersion = VersionV7
)

// VersionRange is the pair of (min, max) versions sent by either peer in the
// SMP handshake. SPEC: "smpVersionRange = minSmpVersion maxSmpVersion".
type VersionRange struct {
	Min, Max Version
}

// EntityID is an opaque queue-or-session identifier. SPEC:
// "entityId = shortString ; queueId or proxySessionId" (length-prefixed,
// up to 255 bytes; queue IDs are 16-24 bytes).
type EntityID []byte

// NoEntity is the empty entity ID used in commands with no associated queue
// (NEW, PING) and certain server responses (IDS).
var NoEntity = EntityID{}

// QueueID is a server-assigned 16-24-byte identifier for one direction of a
// queue. Recipient and sender each get a distinct ID. SPEC:
// "recipientId = shortString ; 16-24 bytes" / "senderId = shortString ; 16-24 bytes".
type QueueID = EntityID

// MsgID is the server-generated 24-byte ID for a delivered message, also used
// as the NaCl nonce for server-to-recipient body encryption.
// SPEC: "msgId = length 24*24OCTET" (within MSG body) — length byte is 0x18.
type MsgID []byte

// CorrID is the 24-byte correlation identifier used to pair a server response
// with the client command that triggered it, and as the NaCl nonce for the
// deniable command authenticator (SMP v7+).
//
// SPEC: "corrId = %x18 24*24 OCTET / %x0 \"\"" — i.e. either 0x18 followed by
// 24 random bytes, or a single 0x00 byte (no correlation; used for server
// notifications such as MSG/END).
type CorrID [24]byte

// NoCorrID returns the zero-length sentinel used by server-pushed messages.
var NoCorrID = CorrID{}

// SessionID is the tls-unique channel binding (RFC 5929) for the current
// transport connection. SPEC: "sessionIdentifier ... derived from transport
// connection handshake". In SMP v7+ it is implied (not transmitted), but is
// still included in the authorized bytes that the authenticator covers.
type SessionID []byte

// AuthMode selects which authentication scheme the client uses for commands
// on a given queue.
//
// SPEC: "Cryptographic algorithms" — clients MUST use either Ed25519
// signatures or NaCl crypto_box-based deniable authenticators.
type AuthMode uint8

const (
	AuthEd25519       AuthMode = iota // recipient commands (recommended)
	AuthCryptoBoxX25519                // sender commands (recommended)
)

// SubscribeMode is the optional flag on NEW that selects whether the server
// auto-subscribes the creator to the new queue on the same transport
// connection. SPEC: "subscribeMode = %s\"S\" / %s\"C\"".
type SubscribeMode byte

const (
	SubscribeOnCreate SubscribeMode = 'S' // server subscribes immediately
	SubscribeManual   SubscribeMode = 'C' // client must SUB later
)

// MsgFlags is the bit-packed flag set on SEND / MSG envelopes.
// SPEC: "msgFlags = notificationFlag reserved"; notificationFlag is "T"/"F",
// reserved is currently a single-byte "0"/"1"-like placeholder.
//
// Haskell Protocol.hs encodes MsgFlags{notification :: Bool} as just the
// notification byte; the "reserved" part in the spec is an extension slot
// that the current code does not actually emit.
type MsgFlags struct {
	Notification bool
}

// NewQueueReq is the body of the NEW command.
//
// SPEC: "create = %s\"NEW \" recipientAuthPublicKey recipientDhPublicKey
//   basicAuth subscribe sndSecure" (modulo version-gated fields).
//
// For the first vertical slice we target SMP v7:
//   - rcvAuthKey is an Ed25519 public key (X.509 encoded).
//   - rcvDhKey is a Curve25519 X25519 public key (X.509 encoded).
//   - basicAuth is absent ('0').
//   - subscribe is 'S' (auto-subscribe so we don't need a separate SUB).
//   - sndSecure is 'F' (v9 field; we'll send 'F' / omit when v < 9).
type NewQueueReq struct {
	// RcvAuthPubKeyDER is the recipient's Ed25519 (or X25519, for crypto_box
	// auth) public key, X.509-encoded. The corresponding private key signs/
	// authenticates the NEW command itself.
	RcvAuthPubKeyDER []byte

	// RcvDHPubKeyDER is the recipient's Curve25519 (X25519) public key,
	// X.509-encoded. The server derives a per-queue secret with this to
	// encrypt the message bodies it delivers in MSG.
	RcvDHPubKeyDER []byte

	// BasicAuth is the server's optional shared password.
	// Empty string = absent ('0' on the wire); non-empty = '1' + length-prefix.
	BasicAuth string

	// SubscribeMode controls auto-subscription. Default SubscribeOnCreate.
	SubscribeMode SubscribeMode

	// SenderCanSecure is the v9 `sndSecure` flag. For v < 9 it is not encoded.
	SenderCanSecure bool
}

// IDSResponse is the server's reply to NEW. SPEC:
//
//	queueIds = %s"IDS " recipientId senderId srvDhPublicKey sndSecure
type IDSResponse struct {
	RecipientID  QueueID
	SenderID     QueueID
	SrvDHPubKey  []byte // server's X25519 public key, X.509 encoded
	SndCanSecure bool   // v9+ only
}

// Message is a delivered MSG (recipient-side view, after stripping the
// server-encryption layer). For the first slice we expose the raw body and
// timestamp; agent-layer decryption (double-ratchet etc.) is out of scope.
//
// SPEC: "message = %s\"MSG\" SP msgId encryptedRcvMsgBody" with
//
//	rcvMsgBody = timestamp msgFlags SP sentMsgBody / msgQuotaExceeded
type Message struct {
	ID    MsgID
	Ts    time.Time
	Flags MsgFlags
	// Body is the decrypted, padded `sentMsgBody` — still SMP-layer wrapped
	// (smpEncMessage). Higher layers strip the smpClientMessage structure.
	Body []byte
	// Quota is true when the server delivered a QUOTA marker instead of
	// a regular body. SPEC: "msgQuotaExceeded = %s\"QUOTA\" SP timestamp".
	Quota bool
}

// Transmission is the wire-level unit: one (corrId, entityId, command) tuple
// plus optional client authorization. Multiple Transmissions are batched into
// a single transport block (SPEC: transmissionCount + transmissionLength prefixes).
type Transmission struct {
	CorrID   CorrID
	EntityID EntityID
	// Command is the raw SMP command bytes after `corrId entityId` — e.g.
	// "NEW " | "SUB" | "SEND " ... — as encoded by encodeCommand.
	Command []byte
	// Authorization is either an Ed25519 signature (64 bytes) or a NaCl
	// crypto_box authenticator (32 bytes), depending on AuthMode of the
	// queue's key.
	Authorization []byte
}

// EncodeCommand serializes a typed command into the raw bytes that follow
// `corrId entityId` in the authorized transmission body.
//
// SPEC ref: Haskell `encodeProtocol v cmd` (Protocol.hs:1681 onward).
func EncodeCommand(v Version, cmd Command) ([]byte, error) {
	e := NewEncoder()
	switch c := cmd.(type) {
	case NewCmd:
		e.Raw([]byte("NEW "))
		if err := e.ShortString(c.Req.RcvAuthPubKeyDER); err != nil {
			return nil, fmt.Errorf("smp: NEW rcvAuthPubKey: %w", err)
		}
		if err := e.ShortString(c.Req.RcvDHPubKeyDER); err != nil {
			return nil, fmt.Errorf("smp: NEW rcvDhPubKey: %w", err)
		}
		if err := e.MaybeShortString(c.Req.BasicAuth != "", []byte(c.Req.BasicAuth)); err != nil {
			return nil, fmt.Errorf("smp: NEW basicAuth: %w", err)
		}
		subMode := byte(c.Req.SubscribeMode)
		if subMode == 0 {
			subMode = byte(SubscribeOnCreate)
		}
		e.Char(subMode)
		if v >= VersionV9 {
			e.Bool(c.Req.SenderCanSecure)
		}
		return e.Bytes(), nil
	case SubCmd:
		return []byte("SUB"), nil
	case SendCmd:
		e.Raw([]byte("SEND "))
		// msgFlags: per Haskell Protocol.hs:889 only the notification byte
		// is encoded; the spec's "reserved" slot is documentation aspiration.
		e.Bool(c.Flags.Notification)
		e.Char(' ')
		e.Tail(c.Body)
		return e.Bytes(), nil
	case AckCmd:
		e.Raw([]byte("ACK "))
		if err := e.ShortString(c.MsgID); err != nil {
			return nil, fmt.Errorf("smp: ACK msgId: %w", err)
		}
		return e.Bytes(), nil
	case PingCmd:
		return []byte("PING"), nil
	default:
		return nil, fmt.Errorf("smp: unknown command type %T", cmd)
	}
}

// DecodeBrokerMsg parses a server BrokerMsg (IDS / MSG / OK / ERR / etc.) from
// the raw command bytes of a received Transmission.
//
// SPEC ref: Haskell `protocolP v tag :: Parser BrokerMsg` (Protocol.hs:1865).
func DecodeBrokerMsg(v Version, raw []byte) (BrokerMsg, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty broker message", ErrBadEncoding)
	}
	switch {
	case bytes.HasPrefix(raw, []byte("IDS ")):
		return decodeIDS(v, raw[4:])
	case bytes.HasPrefix(raw, []byte("MSG ")):
		return decodeMSG(raw[4:])
	case bytes.Equal(raw, []byte("OK")):
		return OKMsg{}, nil
	case bytes.Equal(raw, []byte("PONG")):
		return PongMsg{}, nil
	case bytes.Equal(raw, []byte("END")):
		return EndMsg{}, nil
	case bytes.HasPrefix(raw, []byte("ERR ")):
		return decodeERR(raw[4:])
	default:
		// Show up to 16 bytes of the unexpected prefix for diagnostics.
		end := len(raw)
		if end > 16 {
			end = 16
		}
		return nil, fmt.Errorf("%w: unknown broker message prefix %q", ErrBadEncoding, raw[:end])
	}
}

func decodeIDS(v Version, body []byte) (IDSMsg, error) {
	d := NewDecoder(body)
	rcv, err := d.ShortString()
	if err != nil {
		return IDSMsg{}, fmt.Errorf("smp: IDS recipientId: %w", err)
	}
	snd, err := d.ShortString()
	if err != nil {
		return IDSMsg{}, fmt.Errorf("smp: IDS senderId: %w", err)
	}
	dh, err := d.ShortString()
	if err != nil {
		return IDSMsg{}, fmt.Errorf("smp: IDS srvDhPubKey: %w", err)
	}
	resp := IDSResponse{
		RecipientID: append([]byte(nil), rcv...),
		SenderID:    append([]byte(nil), snd...),
		SrvDHPubKey: append([]byte(nil), dh...),
	}
	if v >= VersionV9 {
		secure, err := d.Bool()
		if err != nil {
			return IDSMsg{}, fmt.Errorf("smp: IDS sndCanSecure: %w", err)
		}
		resp.SndCanSecure = secure
	}
	return IDSMsg{IDS: resp}, nil
}

func decodeMSG(body []byte) (MsgMsg, error) {
	d := NewDecoder(body)
	msgID, err := d.ShortString()
	if err != nil {
		return MsgMsg{}, fmt.Errorf("smp: MSG msgId: %w", err)
	}
	rest := d.Tail()
	// Ts / Flags / Quota live inside the server-encrypted rcvMsgBody — out of
	// scope here; slice 2 will decrypt and parse them.
	return MsgMsg{Msg: Message{
		ID:   append([]byte(nil), msgID...),
		Body: append([]byte(nil), rest...),
	}}, nil
}

func decodeERR(body []byte) (ErrMsg, error) {
	sp := bytes.IndexByte(body, ' ')
	if sp == -1 {
		return ErrMsg{Type: string(body)}, nil
	}
	return ErrMsg{
		Type:   string(body[:sp]),
		Detail: string(body[sp+1:]),
	}, nil
}

// Command is the closed sum of client-issued SMP commands the first vertical
// slice needs to send. Go has no GADTs; we use a small interface and one
// struct per variant.
type Command interface {
	smpCommand() // sealed marker
}

// NewCmd is "NEW " ... . SPEC: section "Create queue command".
type NewCmd struct{ Req NewQueueReq }

// SubCmd is "SUB". SPEC: section "Subscribe to queue".
type SubCmd struct{}

// SendCmd is "SEND <flags> SP <smpEncMessage>". SPEC: section "Send message".
// Body is the already-encrypted smpEncMessage payload (Tail-encoded, no length prefix).
type SendCmd struct {
	Flags MsgFlags
	Body  []byte
}

// AckCmd is "ACK <msgId>". SPEC: section "Acknowledge message delivery".
type AckCmd struct{ MsgID MsgID }

// PingCmd is "PING". SPEC: section "Keep-alive command".
type PingCmd struct{}

func (NewCmd) smpCommand()  {}
func (SubCmd) smpCommand()  {}
func (SendCmd) smpCommand() {}
func (AckCmd) smpCommand()  {}
func (PingCmd) smpCommand() {}

// BrokerMsg is the closed sum of server -> client SMP messages we decode in
// the first slice.
type BrokerMsg interface {
	brokerMsg() // sealed
}

// IDSMsg is the response to NEW.
type IDSMsg struct{ IDS IDSResponse }

// MsgMsg is a delivered queue message.
type MsgMsg struct{ Msg Message }

// OKMsg is the generic success response.
type OKMsg struct{}

// PongMsg is the response to PING.
type PongMsg struct{}

// EndMsg is the END notification when another transport supersedes our SUB.
type EndMsg struct{}

// ErrMsg is an error response. ErrType matches the SPEC error grammar (BLOCK,
// SESSION, CMD ..., AUTH, QUOTA, LARGE_MSG, INTERNAL, ...).
type ErrMsg struct {
	Type   string
	Detail string
}

func (IDSMsg) brokerMsg()  {}
func (MsgMsg) brokerMsg()  {}
func (OKMsg) brokerMsg()   {}
func (PongMsg) brokerMsg() {}
func (EndMsg) brokerMsg()  {}
func (ErrMsg) brokerMsg()  {}

// Error makes ErrMsg satisfy error so callers can `return errResp.Err()`.
func (e ErrMsg) Error() string {
	if e.Detail == "" {
		return "smp: " + e.Type
	}
	return "smp: " + e.Type + ": " + e.Detail
}

// EncodeTransmission writes a single transmission into the authorized form
// expected on the wire. SPEC:
//
//	transmission   = authorization authorized
//	authorized     = sessionIdentifier corrId entityId smpCommand
//
// In SMP v7+ `sessionIdentifier` is implied (sessId == "") in the transmitted
// bytes, but is still prepended to the bytes the authenticator covers.
// `authForBytes` is what the signer/authenticator signs; `wireBytes` is what
// is actually concatenated into the block payload.
//
// Haskell ref: encodeTransmissionForAuth (Protocol.hs:2186).
func EncodeTransmission(v Version, sessID SessionID, t Transmission) (wireBytes, authBytes []byte, err error) {
	_ = v
	_ = sessID
	_ = t
	panic("not implemented")
}

// DecodeBlock parses the multi-transmission body of one transport block into
// individual server transmissions.
//
// SPEC:
//
//	transportBlock     = transmissionCount transmissions
//	transmissionCount  = 1 OCTET
//	transmissionLength = 2 OCTET (word16 NBO) — only present when batching is on.
//
// Batching is on starting from SMP v4 and is always on for the versions we
// target. Haskell ref: tParse (Protocol.hs:2211).
func DecodeBlock(v Version, sessID SessionID, block []byte) ([]Transmission, error) {
	_ = v
	_ = sessID
	_ = block
	panic("not implemented")
}

// ErrBadBlock corresponds to SPEC "BLOCK" / Haskell TEBadBlock.
var ErrBadBlock = errors.New("smp: malformed transport block")

// ErrBadVersion corresponds to SPEC "VERSION" / Haskell TEVersion.
var ErrBadVersion = errors.New("smp: incompatible SMP version")

// ErrBadSession corresponds to SPEC "SESSION" / Haskell TEBadSession.
var ErrBadSession = errors.New("smp: incorrect session ID")

// ErrHandshake wraps a handshake-stage failure (PARSE / IDENTITY / BAD_AUTH).
type ErrHandshake struct{ Reason string }

func (e ErrHandshake) Error() string { return "smp: handshake error: " + e.Reason }
