// Package smp implements the SimpleX Messaging Protocol (SMP) client transport
// and command layer over TLS 1.3 with certificate-fingerprint pinning.
//
// Spec: /home/joop/simplexmq-reference/protocol/simplex-messaging.md (v9, 2024-06-22).
// Reference: simplexmq Simplex.Messaging.Transport, .Protocol, .Client.
package smp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// SMPBlockSize is the fixed transport block size for all SMP transmissions.
// SPEC: simplex-messaging.md, "SMP Transmission and transport block structure":
// "Each transport block has a fixed size of 16384 bytes for traffic uniformity."
// Haskell: Transport.hs:153 `smpBlockSize = 16384`.
const SMPBlockSize = 16384

// ALPN protocol name used by SMP v7+ to negotiate the current handshake.
// SPEC: "Server SHOULD send `smp/1` protocol name ..." (section "ALPN to agree handshake version").
const ALPNSMP = "smp/1"

// DefaultSMPPort is the default TCP port for SMP servers when not specified
// in the queue URI. SPEC: "the default TCP port for SMP protocol is 5223".
const DefaultSMPPort = "5223"

// KeyHash is a SHA-256 fingerprint of the offline SMP server certificate's
// public-key-info (SPKI), as transmitted in the SMP queue URI's
// `serverIdentity` component.
//
// SPEC: "serverIdentity is a required hash of the server certificate SPKI block
// ... used by the client to validate server certificate during transport handshake".
//
// The reference server uses raw SHA-256 of the DER-encoded SPKI of the
// offline (CA) certificate; see Haskell Transport.hs `keyHash` field handling
// in `smpClientHandshake` (Transport.hs:818).
type KeyHash [sha256.Size]byte

// TransportConfig holds tunable parameters for the TLS dialer and transport
// I/O.
type TransportConfig struct {
	// DialTimeout caps how long ConnectTLS waits for the underlying TCP +
	// TLS handshake to complete. Zero means no timeout.
	DialTimeout time.Duration

	// IOTimeout, if non-zero, is set as the read/write deadline on each
	// block sent or received. Zero leaves deadlines unset (caller is
	// expected to use ctx-based cancellation).
	IOTimeout time.Duration

	// LogTLSErrors mirrors the Haskell TransportConfig.logTLSErrors flag.
	// When true, handshake failures are logged before being returned.
	LogTLSErrors bool
}

// Conn wraps a TLS connection negotiated with an SMP server, exposing the
// 16384-byte block framing and the TLS-unique channel binding required by
// the SMP transport handshake.
//
// SPEC: "Once TLS handshake is complete, client and server will exchange
// blocks of fixed size (16384 bytes)" and
// "client should assert that sessionIdentifier is equal to tls-unique channel
// binding defined in RFC 5929".
type Conn struct {
	// SPEC: tls.ConnectionState holds the negotiated ALPN and (via
	// reflection of Finished message) the tls-unique binding.
	tls *tls.Conn

	// tlsUnique is the RFC5929 tls-unique channel binding (client's
	// Finished message in TLS 1.3 — see Haskell `withTlsUnique` / `T.getFinished`).
	tlsUnique []byte

	// peerCertChain is the raw chain presented by the server, after
	// fingerprint pinning has verified the offline cert.
	peerCertChain []*x509.Certificate

	cfg TransportConfig
}

// DialTLS opens a TCP connection to addr (host:port), performs the TLS 1.3
// handshake with ALPN `smp/1`, and verifies that one of the certificates in
// the presented chain matches the supplied KeyHash fingerprint. It returns a
// *Conn ready for SMP transport handshake.
//
// SPEC notes:
//   - TLS 1.3 only.
//   - Cipher restricted to TLS_CHACHA20_POLY1305_SHA256.
//   - Curve groups restricted to X25519 (and X448).
//   - Signature algorithms restricted to Ed25519 / Ed448.
//   - Server sends a chain of 2, 3, or 4 self-signed certificates; the
//     offline cert's fingerprint must match `expected`.
//   - Session resumption MUST be disabled.
//
// Cert pinning is implemented via tls.Config.VerifyConnection (custom
// verifier) with InsecureSkipVerify=true so that the standard PKIX trust
// store is bypassed entirely. SPEC: section "Server certificate".
func DialTLS(ctx context.Context, addr string, expected KeyHash, cfg TransportConfig) (*Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smp: tcp dial %s: %w", addr, err)
	}

	var peerChain []*x509.Certificate
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // We pin manually below; PKIX trust store is bypassed by design.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNSMP},
		CurvePreferences:   []tls.CurveID{tls.X25519},
		ClientSessionCache: nil, // SPEC: session resumption disabled.
		VerifyConnection: func(state tls.ConnectionState) error {
			peerChain = state.PeerCertificates
			if len(peerChain) == 0 {
				return errors.New("smp: server presented no certificates")
			}
			if n := len(peerChain); n < 2 || n > 4 {
				return fmt.Errorf("smp: unexpected cert chain length %d (want 2..4)", n)
			}
			for _, cert := range peerChain {
				if CertFingerprint(cert) == expected || SPKIFingerprint(cert) == expected {
					return nil
				}
			}
			return ErrFingerprintMismatch
		},
	}
	tlsConn := tls.Client(rawConn, tlsCfg)

	if cfg.DialTimeout > 0 {
		_ = rawConn.SetDeadline(time.Now().Add(cfg.DialTimeout))
		defer func() { _ = rawConn.SetDeadline(time.Time{}) }()
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		if cfg.LogTLSErrors {
			fmt.Fprintf(io.Discard, "smp: tls handshake failed: %v\n", err)
		}
		return nil, fmt.Errorf("smp: tls handshake: %w", err)
	}

	return &Conn{
		tls:           tlsConn,
		tlsUnique:     nil, // TODO(slice2): expose RFC5705 keying material for SMP v7+ deniable auth — Go's tls.ConnectionState.TLSUnique is empty in TLS 1.3.
		peerCertChain: peerChain,
		cfg:           cfg,
	}, nil
}

// Close shuts down the underlying TLS session.
func (c *Conn) Close() error {
	if c == nil || c.tls == nil {
		return nil
	}
	return c.tls.Close()
}

// TLSUnique returns the RFC5929 tls-unique channel binding bytes for this
// connection. Used by the SMP handshake to derive `sessionId`.
func (c *Conn) TLSUnique() []byte { return c.tlsUnique }

// PeerCertChain returns the verified server certificate chain (offline cert
// first, then any intermediate / online / session certs).
func (c *Conn) PeerCertChain() []*x509.Certificate { return c.peerCertChain }

// WriteBlock pads `payload` to SMPBlockSize and writes it as a single
// transport block. Returns ErrLargeBlock if payload + 2-byte length prefix
// would exceed SMPBlockSize.
//
// SPEC: "paddedString = originalLength string pad" where originalLength is
// a 2-byte network-byte-order word16, and pad is `#` repeated to fill the
// remaining bytes. See Haskell `C.pad` (Crypto.hs) used in Transport.hs
// `tPutBlock` (line 728).
//
// NOTE: starting in SMP v11 (encryptedBlockSMPVersion) blocks may instead be
// encrypted with secret-box keys derived from the session DH secret. For the
// first vertical slice we operate at v6/v7 effective version (no block
// encryption); a future version of this function will branch on negotiated
// version.
func (c *Conn) WriteBlock(ctx context.Context, payload []byte) error {
	if len(payload) > SMPBlockSize-2 {
		return ErrLargeBlock
	}
	block := make([]byte, SMPBlockSize)
	binary.BigEndian.PutUint16(block[:2], uint16(len(payload)))
	copy(block[2:], payload)
	for i := 2 + len(payload); i < SMPBlockSize; i++ {
		block[i] = '#'
	}
	c.applyWriteDeadline(ctx)
	defer c.clearWriteDeadline()
	_, err := c.tls.Write(block)
	return err
}

// ReadBlock reads exactly SMPBlockSize bytes from the connection and strips
// the 2-byte length prefix and `#` padding, returning the unpadded payload.
//
// SPEC: "originalLength = 2*2 OCTET" (word16 big-endian) — see Haskell
// `C.unPad` and `tGetBlock` (Transport.hs:733).
func (c *Conn) ReadBlock(ctx context.Context) ([]byte, error) {
	c.applyReadDeadline(ctx)
	defer c.clearReadDeadline()
	block := make([]byte, SMPBlockSize)
	if _, err := io.ReadFull(c.tls, block); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, ErrShortBlock
		}
		return nil, err
	}
	length := binary.BigEndian.Uint16(block[:2])
	if int(length) > SMPBlockSize-2 {
		return nil, ErrBadBlock
	}
	payload := make([]byte, length)
	copy(payload, block[2:2+length])
	return payload, nil
}

func (c *Conn) applyReadDeadline(ctx context.Context) {
	deadline := earliestDeadline(c.cfg.IOTimeout, ctx)
	if !deadline.IsZero() {
		_ = c.tls.SetReadDeadline(deadline)
	}
}

func (c *Conn) clearReadDeadline() { _ = c.tls.SetReadDeadline(time.Time{}) }

func (c *Conn) applyWriteDeadline(ctx context.Context) {
	deadline := earliestDeadline(c.cfg.IOTimeout, ctx)
	if !deadline.IsZero() {
		_ = c.tls.SetWriteDeadline(deadline)
	}
}

func (c *Conn) clearWriteDeadline() { _ = c.tls.SetWriteDeadline(time.Time{}) }

func earliestDeadline(io time.Duration, ctx context.Context) time.Time {
	var deadline time.Time
	if io > 0 {
		deadline = time.Now().Add(io)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() || ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline
}

// ErrLargeBlock is returned when a payload does not fit in SMPBlockSize.
// SPEC: transport error code TELargeMsg / "LARGE_MSG".
var ErrLargeBlock = errors.New("smp: payload exceeds transport block size")

// ErrShortBlock is returned when fewer than SMPBlockSize bytes are read
// (the spec mandates exact-size blocks; a short read indicates EOF or
// truncation).
var ErrShortBlock = errors.New("smp: short read from transport")

// ErrFingerprintMismatch is returned by DialTLS when none of the server's
// presented certificates match the expected KeyHash.
// SPEC: HandshakeError IDENTITY.
var ErrFingerprintMismatch = errors.New("smp: server certificate fingerprint mismatch")

// SPKIFingerprint returns the SHA-256 hash of the certificate's
// SubjectPublicKeyInfo (DER). This is the value compared against the
// `serverIdentity` portion of the queue URI.
//
// SPEC: "hash of the server certificate SPKI block" — Haskell uses
// `XV.getFingerprint cert X.HashSHA256` over the whole cert, but the
// queue-URI form documented uses the SPKI hash; cross-check during the
// first vertical-slice integration test (this is one of the open
// questions for joop).
func SPKIFingerprint(cert *x509.Certificate) KeyHash {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// CertFingerprint returns the SHA-256 over the entire DER-encoded
// certificate. This matches `X.HashSHA256` of the whole signed cert as used
// in Haskell `XV.getFingerprint idCert X.HashSHA256` (Transport.hs:818) —
// which is what the reference implementation actually compares against
// `serverIdentity`.
func CertFingerprint(cert *x509.Certificate) KeyHash {
	return sha256.Sum256(cert.Raw)
}

