package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LaPingvino/simplex-go/smp"
)

func sampleSMPURI(t *testing.T) string {
	t.Helper()
	var fp smp.KeyHash
	for i := range fp {
		fp[i] = byte(i + 1)
	}
	sid := bytes.Repeat([]byte{0x42}, 24)
	dh := bytes.Repeat([]byte{0x80}, smp.X25519KeySize)
	return smp.SMPQueueURI{
		ServerFingerprint: fp,
		Host:              "smp14.simplex.im",
		Port:              5223,
		SenderID:          sid,
		ClientVRange:      smp.VersionRange{Min: 1, Max: 7},
		DHPubKey:          dh,
	}.String()
}

func TestPairAddsBuddyFromURI(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	uri := sampleSMPURI(t)
	if err := cmdPair([]string{"alice", uri}); err != nil {
		t.Fatalf("pair: %v", err)
	}

	s, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Buddies) != 1 {
		t.Fatalf("buddies after pair: got %d want 1", len(s.Buddies))
	}
	b := s.Buddies[0]
	if b.Name != "alice" {
		t.Errorf("name: got %q want alice", b.Name)
	}
	if b.SimpleXLink != uri {
		t.Errorf("link: got %q want %q", b.SimpleXLink, uri)
	}
	if b.SharedSecret == "" {
		t.Error("shared secret was not derived")
	}
}

func TestPairDeterministicSecret(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	uri := sampleSMPURI(t)

	if err := cmdPair([]string{"alice", uri}); err != nil {
		t.Fatal(err)
	}
	s, _ := loadState()
	secret1 := s.Buddies[0].SharedSecret

	// Different name, same URI — derived secret must match.
	tmp2 := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp2)
	if err := cmdPair([]string{"bob", uri}); err != nil {
		t.Fatal(err)
	}
	s2, _ := loadState()
	secret2 := s2.Buddies[0].SharedSecret

	if secret1 != secret2 {
		t.Fatalf("same URI -> different secrets:\n  %s\n  %s", secret1, secret2)
	}
}

func TestPairRejectsDuplicateName(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	uri := sampleSMPURI(t)

	if err := cmdPair([]string{"alice", uri}); err != nil {
		t.Fatal(err)
	}
	err := cmdPair([]string{"alice", uri})
	if err == nil || !strings.Contains(err.Error(), "already paired") {
		t.Fatalf("dup pair: got %v want 'already paired'", err)
	}
}

func TestPairRejectsBadURI(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := cmdPair([]string{"alice", "not-a-uri"}); err == nil {
		t.Fatal("bad URI: expected error")
	}
	if err := cmdPair([]string{}); err == nil {
		t.Fatal("no args: expected error")
	}
	if err := cmdPair([]string{"only-one-arg"}); err == nil {
		t.Fatal("one arg: expected error")
	}
	if err := cmdPair([]string{"", sampleSMPURI(t)}); err == nil {
		t.Fatal("empty name: expected error")
	}
}

func TestDeriveProximitySecretReproducible(t *testing.T) {
	var fp smp.KeyHash
	for i := range fp {
		fp[i] = 0xAB
	}
	uri := smp.SMPQueueURI{
		ServerFingerprint: fp,
		Host:              "host",
		Port:              5223,
		SenderID:          bytes.Repeat([]byte{1}, 16),
		ClientVRange:      smp.VersionRange{Min: 1, Max: 7},
		DHPubKey:          bytes.Repeat([]byte{2}, smp.X25519KeySize),
	}
	s1 := deriveProximitySecret(uri)
	s2 := deriveProximitySecret(uri)
	if !bytes.Equal(s1, s2) {
		t.Fatal("deriveProximitySecret is not deterministic")
	}
	if len(s1) != 32 {
		t.Fatalf("secret length: got %d want 32 (SHA-256)", len(s1))
	}

	// Different URI → different secret.
	uri2 := uri
	uri2.SenderID = bytes.Repeat([]byte{99}, 16)
	s3 := deriveProximitySecret(uri2)
	if bytes.Equal(s1, s3) {
		t.Fatal("different URI yields same secret")
	}
}

