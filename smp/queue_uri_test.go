package smp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSMPQueueURIRoundTrip(t *testing.T) {
	var fp KeyHash
	for i := range fp {
		fp[i] = byte(i)
	}
	sid := bytes.Repeat([]byte{0xAB}, 24)
	dh := bytes.Repeat([]byte{0xCD}, X25519KeySize)

	original := SMPQueueURI{
		ServerFingerprint: fp,
		Host:              "smp14.simplex.im",
		Port:              5223,
		SenderID:          sid,
		ClientVRange:      VersionRange{Min: 1, Max: 15},
		DHPubKey:          dh,
	}

	uri := original.String()
	if !strings.HasPrefix(uri, "smp://") {
		t.Fatalf("URI missing smp:// prefix: %q", uri)
	}
	if !strings.Contains(uri, "@smp14.simplex.im:5223/") {
		t.Errorf("URI missing host:port: %q", uri)
	}
	if !strings.Contains(uri, "#/?") {
		t.Errorf("URI missing #/? fragment marker: %q", uri)
	}

	parsed, err := ParseSMPQueueURI(uri)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.ServerFingerprint != original.ServerFingerprint {
		t.Errorf("fingerprint: got %x want %x", parsed.ServerFingerprint, original.ServerFingerprint)
	}
	if parsed.Host != original.Host {
		t.Errorf("host: got %q want %q", parsed.Host, original.Host)
	}
	if parsed.Port != original.Port {
		t.Errorf("port: got %d want %d", parsed.Port, original.Port)
	}
	if !bytes.Equal(parsed.SenderID, original.SenderID) {
		t.Errorf("senderId: got %x want %x", parsed.SenderID, original.SenderID)
	}
	if parsed.ClientVRange != original.ClientVRange {
		t.Errorf("vrange: got %+v want %+v", parsed.ClientVRange, original.ClientVRange)
	}
	if !bytes.Equal(parsed.DHPubKey, original.DHPubKey) {
		t.Errorf("dh: got %x want %x", parsed.DHPubKey, original.DHPubKey)
	}
}

func TestSMPQueueURIDefaultPort(t *testing.T) {
	var fp KeyHash
	sid := bytes.Repeat([]byte{1}, 16) // min length
	dh := bytes.Repeat([]byte{2}, X25519KeySize)

	// No port → 5223 default
	uri := "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) +
		"@example.com/" + base64.RawURLEncoding.EncodeToString(sid) +
		"#/?v=1-7&dh=" + base64.RawURLEncoding.EncodeToString(dh)

	parsed, err := ParseSMPQueueURI(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Port != 5223 {
		t.Errorf("default port: got %d want 5223", parsed.Port)
	}
}

func TestSMPQueueURISingleVersion(t *testing.T) {
	var fp KeyHash
	sid := bytes.Repeat([]byte{1}, 16)
	dh := bytes.Repeat([]byte{2}, X25519KeySize)
	uri := "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) +
		"@h:1234/" + base64.RawURLEncoding.EncodeToString(sid) +
		"#/?v=7&dh=" + base64.RawURLEncoding.EncodeToString(dh)
	parsed, err := ParseSMPQueueURI(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.ClientVRange.Min != 7 || parsed.ClientVRange.Max != 7 {
		t.Errorf("single version: got %+v want {7,7}", parsed.ClientVRange)
	}
}

func TestSMPQueueURIErrors(t *testing.T) {
	var fp KeyHash
	sid := bytes.Repeat([]byte{1}, 16)
	dh := bytes.Repeat([]byte{2}, X25519KeySize)
	good := "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) +
		"@h:1/" + base64.RawURLEncoding.EncodeToString(sid) +
		"#/?v=1-7&dh=" + base64.RawURLEncoding.EncodeToString(dh)

	bads := map[string]string{
		"wrong scheme":              "https://foo",
		"no @ for fingerprint":      "smp://h/q#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"bad fingerprint base64":    "smp://###@h/q#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"fingerprint wrong length":  "smp://" + base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) + "@h/" + base64.RawURLEncoding.EncodeToString(sid) + "#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"no slash for sid":          "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"missing # fragment":        "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString(sid),
		"missing v param":           "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString(sid) + "#/?dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"missing dh param":          "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString(sid) + "#/?v=1",
		"dh wrong length":           "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString(sid) + "#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString([]byte{1, 2}),
		"senderId too short":        "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString([]byte{1, 2}) + "#/?v=1&dh=" + base64.RawURLEncoding.EncodeToString(dh),
		"vrange min greater than max": "smp://" + base64.RawURLEncoding.EncodeToString(fp[:]) + "@h:1/" + base64.RawURLEncoding.EncodeToString(sid) + "#/?v=9-3&dh=" + base64.RawURLEncoding.EncodeToString(dh),
	}

	// First confirm `good` actually parses.
	if _, err := ParseSMPQueueURI(good); err != nil {
		t.Fatalf("baseline good URI failed: %v", err)
	}

	for name, badURI := range bads {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSMPQueueURI(badURI); err == nil {
				t.Fatalf("expected error for %s, parse succeeded", name)
			} else if !errors.Is(err, ErrBadQueueURI) {
				t.Fatalf("expected ErrBadQueueURI for %s, got %v", name, err)
			}
		})
	}
}

func TestVersionRangeParse(t *testing.T) {
	cases := []struct {
		in   string
		min  Version
		max  Version
		fail bool
	}{
		{"1-15", 1, 15, false},
		{"7", 7, 7, false},
		{"7-7", 7, 7, false},
		{"9-3", 0, 0, true},
		{"abc", 0, 0, true},
		{"-5", 0, 0, true},
		{"5-", 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			vr, err := parseVersionRange(c.in)
			if c.fail {
				if err == nil {
					t.Fatalf("expected error, got %+v", vr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if vr.Min != c.min || vr.Max != c.max {
				t.Fatalf("got %+v want {%d,%d}", vr, c.min, c.max)
			}
		})
	}
}
