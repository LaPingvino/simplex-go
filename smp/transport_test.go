package smp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// testServer spins up an in-process TLS 1.3 echo server with a self-signed
// chain of `chainLen` Ed25519 certs (must be 2..4 to pass the chain-length
// check in DialTLS). The first cert in the chain is treated as the offline
// (CA) cert; its full-DER SHA-256 is returned as the pinning fingerprint.
type testServer struct {
	addr        string
	caFP        KeyHash
	leafCertFP  KeyHash
	leafSPKIFP  KeyHash
	listener    net.Listener
	wg          sync.WaitGroup
	stopOnce    sync.Once
	stopped     chan struct{}
}

func newTestServer(t *testing.T, chainLen int) *testServer {
	t.Helper()
	if chainLen < 1 || chainLen > 4 {
		t.Fatalf("chainLen %d out of range", chainLen)
	}

	// Build chain: chain[0] = self-signed CA, chain[1..] = leaves signed by CA.
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smp-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	chainDER := [][]byte{}
	var leafPriv ed25519.PrivateKey = caPriv
	if chainLen == 1 {
		chainDER = append(chainDER, caDER)
	} else {
		// Leaf at index 0, then intermediates, then CA last — standard
		// Go tls.Certificate.Certificate order (leaf-first, root-last).
		// Our DialTLS only cares about *one of* the certs matching; we put
		// leaf at front and CA at back to mirror real-world ordering.
		for i := 0; i < chainLen-1; i++ {
			leafPub, lp, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("gen leaf key %d: %v", i, err)
			}
			leafTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(int64(2 + i)),
				Subject:               pkix.Name{CommonName: "smp-test-leaf"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				DNSNames:              []string{"localhost"},
				IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caPriv)
			if err != nil {
				t.Fatalf("sign leaf %d: %v", i, err)
			}
			// Prepend leaves so the first one ends up at index 0.
			chainDER = append([][]byte{leafDER}, chainDER...)
			if i == 0 {
				leafPriv = lp
			}
		}
		chainDER = append(chainDER, caDER)
	}

	tlsCert := tls.Certificate{
		Certificate: chainDER,
		PrivateKey:  leafPriv,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNSMP},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	leafCert, _ := x509.ParseCertificate(chainDER[0])
	srv := &testServer{
		addr:       ln.Addr().String(),
		caFP:       CertFingerprint(caCert),
		leafCertFP: CertFingerprint(leafCert),
		leafSPKIFP: SPKIFingerprint(leafCert),
		listener:   ln,
		stopped:    make(chan struct{}),
	}

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.wg.Add(1)
			go srv.echo(conn)
		}
	}()

	t.Cleanup(srv.Close)
	return srv
}

func (s *testServer) echo(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	buf := make([]byte, SMPBlockSize)
	for {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

func (s *testServer) Close() {
	s.stopOnce.Do(func() {
		_ = s.listener.Close()
		close(s.stopped)
	})
	s.wg.Wait()
}

func TestBlockRoundTrip(t *testing.T) {
	srv := newTestServer(t, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialTLS(ctx, srv.addr, srv.caFP, TransportConfig{
		DialTimeout: 2 * time.Second,
		IOTimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("kozi-"), 20) // 100 bytes
	if err := conn.WriteBlock(ctx, payload); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	got, err := conn.ReadBlock(ctx)
	if err != nil {
		t.Fatalf("ReadBlock: %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatalf("round-trip mismatch:\n  got  %q\n  want %q", got, payload)
	}
}

func TestBlockAtMaxSize(t *testing.T) {
	srv := newTestServer(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTLS(ctx, srv.addr, srv.caFP, TransportConfig{IOTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()

	max := SMPBlockSize - 2
	payload := bytes.Repeat([]byte{0xAB}, max)
	if err := conn.WriteBlock(ctx, payload); err != nil {
		t.Fatalf("WriteBlock at max: %v", err)
	}
	got, err := conn.ReadBlock(ctx)
	if err != nil {
		t.Fatalf("ReadBlock at max: %v", err)
	}
	if len(got) != max || !bytes.Equal(got, payload) {
		t.Fatalf("max-size round-trip mismatch, got %d bytes want %d", len(got), max)
	}
}

func TestWriteBlockOversize(t *testing.T) {
	// A nil Conn would crash; we need a real one but never write to it past
	// the size guard. Use a fresh server so cleanup is clean.
	srv := newTestServer(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTLS(ctx, srv.addr, srv.caFP, TransportConfig{})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, SMPBlockSize-1) // strictly larger than SMPBlockSize-2
	err = conn.WriteBlock(ctx, payload)
	if !errors.Is(err, ErrLargeBlock) {
		t.Fatalf("WriteBlock oversize: got %v, want ErrLargeBlock", err)
	}
}

func TestFingerprintMismatch(t *testing.T) {
	srv := newTestServer(t, 2)

	var bogus KeyHash
	for i := range bogus {
		bogus[i] = 0xFF
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := DialTLS(ctx, srv.addr, bogus, TransportConfig{DialTimeout: 2 * time.Second})
	if err == nil {
		t.Fatal("DialTLS with bogus fingerprint: expected error, got nil")
	}
	// The error is wrapped by tls.HandshakeContext; check it surfaces our
	// sentinel underneath.
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("DialTLS with bogus fingerprint: got %v, want ErrFingerprintMismatch", err)
	}
}

func TestChainLengthRejected(t *testing.T) {
	srv := newTestServer(t, 1) // single self-signed cert, below the 2..4 window

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := DialTLS(ctx, srv.addr, srv.caFP, TransportConfig{DialTimeout: 2 * time.Second})
	if err == nil {
		t.Fatal("DialTLS with 1-cert chain: expected error, got nil")
	}
	// Generic wrapped error; we just want non-nil and the "chain length"
	// message visible somewhere in the chain.
	if !contains(err.Error(), "chain length") {
		t.Fatalf("DialTLS chain-length error: got %q, want to contain 'chain length'", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		(len(haystack) > 0 && (bytesContains([]byte(haystack), []byte(needle)))))
}

func bytesContains(b, sub []byte) bool { return bytes.Contains(b, sub) }
