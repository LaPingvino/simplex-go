package smp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// runSMPClientHandshake drives the client side of the SMP handshake on an
// already-TLS-handshook Conn. Returns the populated HandshakeParams ready
// to feed to NewClient.
//
// SPEC (simplexmq Transport.hs:792 smpClientHandshake):
//
//  1. Read paddedServerHello block → SMPServerHandshake
//  2. Assert server's sessionID matches ours
//  3. NegotiateVersion across (client range ∩ server range)
//  4. For v≥V7: if ownAuthPriv is nil, generate ephemeral X25519 keypair
//     (loses the priv after handshake); otherwise derive pub from ownAuthPriv
//  5. Write paddedClientHello block with chosen version, keyHash, own pub
//
// Returns HandshakeParams with the negotiated version, sessionID, and
// (for v≥V7) the server's auth pub key. The caller can use PeerAuthPubKey
// + their own ownAuthPriv to construct X25519AuthSigner for later commands.
func runSMPClientHandshake(ctx context.Context, conn *Conn, expected KeyHash, sessionID SessionID, ownAuthPriv []byte) (HandshakeParams, error) {
	// 1. Read paddedServerHello.
	helloBytes, err := conn.ReadBlock(ctx)
	if err != nil {
		return HandshakeParams{}, fmt.Errorf("smp: read serverHello: %w", err)
	}
	srv, err := DecodeSMPServerHandshake(helloBytes)
	if err != nil {
		return HandshakeParams{}, fmt.Errorf("smp: decode serverHello: %w", err)
	}

	// 2. Session ID match.
	if !bytes.Equal(srv.SessionID, sessionID) {
		return HandshakeParams{}, fmt.Errorf("%w: server=%x ours=%x",
			ErrBadSession, srv.SessionID, sessionID)
	}

	// 3. Version negotiation.
	v, err := NegotiateVersion(srv.VersionRange)
	if err != nil {
		return HandshakeParams{}, err
	}

	// 4. X25519 keypair for v≥V7 deniable auth. Generate ephemeral if caller
	//    didn't supply one.
	var ownPub []byte
	if v >= VersionV7 {
		if ownAuthPriv == nil {
			curve := ecdh.X25519()
			k, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return HandshakeParams{}, fmt.Errorf("smp: generate ephemeral X25519: %w", err)
			}
			ownAuthPriv = k.Bytes()
			ownPub = k.PublicKey().Bytes()
		} else {
			if len(ownAuthPriv) != X25519KeySize {
				return HandshakeParams{}, fmt.Errorf("smp: ownAuthPriv must be %d bytes, got %d", X25519KeySize, len(ownAuthPriv))
			}
			curve := ecdh.X25519()
			k, err := curve.NewPrivateKey(ownAuthPriv)
			if err != nil {
				return HandshakeParams{}, fmt.Errorf("smp: parse ownAuthPriv: %w", err)
			}
			ownPub = k.PublicKey().Bytes()
		}
	}

	// 5. Write paddedClientHello.
	cliHello := SMPClientHandshake{
		Version:       v,
		KeyHash:       expected,
		AuthPubKeyRaw: ownPub, // nil if v<V7
	}
	cliBytes, err := EncodeSMPClientHandshake(cliHello)
	if err != nil {
		return HandshakeParams{}, fmt.Errorf("smp: encode clientHello: %w", err)
	}
	if err := conn.WriteBlock(ctx, cliBytes); err != nil {
		return HandshakeParams{}, fmt.Errorf("smp: write clientHello: %w", err)
	}

	// Extract server's auth pub key from its hello if it provided one.
	//
	// SIMPLIFICATION (slice 2 follow-up): the spec sends CertChainPubKey =
	// (encodeCertChain certChain, SignedObject signedPubKey). We don't parse
	// the X.509 cert chain here; we expose the raw blob to the caller and
	// only attempt to interpret it as a raw 32-byte X25519 key if the size
	// happens to match. Real interop with simplexmq's smp-server will need
	// proper cert-chain parsing + signature verification.
	var peerPub []byte
	if v >= VersionV7 && len(srv.AuthPubKeyRaw) == X25519KeySize {
		peerPub = append([]byte(nil), srv.AuthPubKeyRaw...)
	}

	return HandshakeParams{
		Version:        v,
		SessID:         append(SessionID(nil), sessionID...),
		PeerAuthPubKey: peerPub,
		BlockSize:      SMPBlockSize,
	}, nil
}
