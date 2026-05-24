package smp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// SMPQueueURI is one SMP queue address as exchanged between SimpleX peers
// out-of-band. Minimal form supported in this iteration:
//
//	smp://<base64url(fingerprint)>@<host>:<port>/<base64url(senderId)>#/?v=<min>-<max>&dh=<base64url(dhPubKey)>
//
// Not yet supported (deferred to later iterations):
//   - Multi-host with srv= query param
//   - queueMode (q=m / q=c) and sender-can-secure (k=s) flags
//   - The outer ConnectionRequestUri wrapper (simplex:/invitation#/?...)
//
// SPEC: simplexmq/src/Simplex/Messaging/Agent/Protocol.hs:1380 (instance
// StrEncoding SMPQueueUri).
type SMPQueueURI struct {
	// ServerFingerprint is the SHA-256 of the SMP server's offline CA cert
	// (the same KeyHash used by DialTLS).
	ServerFingerprint KeyHash
	// Host is the SMP server hostname or IP.
	Host string
	// Port defaults to 5223 if absent.
	Port uint16
	// SenderID is the server-assigned 16-24 byte queue id.
	SenderID []byte
	// ClientVRange is the SMP client version range this queue speaks.
	ClientVRange VersionRange
	// DHPubKey is the X25519 public key the recipient uses to derive the
	// per-queue secret with the server.
	DHPubKey []byte
}

// ParseSMPQueueURI parses a minimal SMP queue URI as defined above.
func ParseSMPQueueURI(s string) (SMPQueueURI, error) {
	const scheme = "smp://"
	if !strings.HasPrefix(s, scheme) {
		return SMPQueueURI{}, fmt.Errorf("%w: expected %q prefix, got %q", ErrBadQueueURI, scheme, firstN(s, 16))
	}
	rest := s[len(scheme):]

	// Split off the fragment-query first: <auth-path>#/?<query>
	hashIdx := strings.Index(rest, "#")
	if hashIdx == -1 {
		return SMPQueueURI{}, fmt.Errorf("%w: missing '#' fragment with version+dh params", ErrBadQueueURI)
	}
	authPath, frag := rest[:hashIdx], rest[hashIdx+1:]

	// Fragment must start with "/?" — SimpleX convention.
	frag = strings.TrimPrefix(frag, "/")
	frag = strings.TrimPrefix(frag, "?")

	// Split auth@host:port/senderId
	atIdx := strings.Index(authPath, "@")
	if atIdx == -1 {
		return SMPQueueURI{}, fmt.Errorf("%w: missing '@' between fingerprint and host", ErrBadQueueURI)
	}
	fpStr := authPath[:atIdx]
	hostPathStr := authPath[atIdx+1:]

	slashIdx := strings.Index(hostPathStr, "/")
	if slashIdx == -1 {
		return SMPQueueURI{}, fmt.Errorf("%w: missing '/' between host and senderId", ErrBadQueueURI)
	}
	hostPortStr := hostPathStr[:slashIdx]
	sidStr := hostPathStr[slashIdx+1:]

	// Strip trailing '/' from sidStr that may have been added before the '#'.
	sidStr = strings.TrimSuffix(sidStr, "/")

	// Parse fingerprint.
	fpBytes, err := base64.RawURLEncoding.DecodeString(fpStr)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: decode fingerprint: %v", ErrBadQueueURI, err)
	}
	if len(fpBytes) != 32 {
		return SMPQueueURI{}, fmt.Errorf("%w: fingerprint must be 32 bytes (SHA-256), got %d", ErrBadQueueURI, len(fpBytes))
	}
	var fp KeyHash
	copy(fp[:], fpBytes)

	// Parse host:port.
	host, port, err := parseHostPort(hostPortStr)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: %v", ErrBadQueueURI, err)
	}

	// Parse senderId.
	sid, err := base64.RawURLEncoding.DecodeString(sidStr)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: decode senderId: %v", ErrBadQueueURI, err)
	}
	if len(sid) < 16 || len(sid) > 24 {
		return SMPQueueURI{}, fmt.Errorf("%w: senderId must be 16-24 bytes, got %d", ErrBadQueueURI, len(sid))
	}

	// Parse query: v=<min>-<max>&dh=<base64url>
	q, err := url.ParseQuery(frag)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: parse fragment query: %v", ErrBadQueueURI, err)
	}
	vrStr := q.Get("v")
	if vrStr == "" {
		return SMPQueueURI{}, fmt.Errorf("%w: missing 'v' query param (version range)", ErrBadQueueURI)
	}
	vr, err := parseVersionRange(vrStr)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: %v", ErrBadQueueURI, err)
	}

	dhStr := q.Get("dh")
	if dhStr == "" {
		return SMPQueueURI{}, fmt.Errorf("%w: missing 'dh' query param", ErrBadQueueURI)
	}
	dh, err := base64.RawURLEncoding.DecodeString(dhStr)
	if err != nil {
		return SMPQueueURI{}, fmt.Errorf("%w: decode dh: %v", ErrBadQueueURI, err)
	}
	if len(dh) != X25519KeySize {
		return SMPQueueURI{}, fmt.Errorf("%w: dh key must be %d bytes, got %d", ErrBadQueueURI, X25519KeySize, len(dh))
	}

	return SMPQueueURI{
		ServerFingerprint: fp,
		Host:              host,
		Port:              port,
		SenderID:          sid,
		ClientVRange:      vr,
		DHPubKey:          dh,
	}, nil
}

// String generates the canonical URI form of u. Round-trips through ParseSMPQueueURI.
func (u SMPQueueURI) String() string {
	port := u.Port
	if port == 0 {
		port = 5223
	}
	q := url.Values{}
	q.Set("v", fmt.Sprintf("%d-%d", u.ClientVRange.Min, u.ClientVRange.Max))
	q.Set("dh", base64.RawURLEncoding.EncodeToString(u.DHPubKey))
	return fmt.Sprintf(
		"smp://%s@%s:%d/%s#/?%s",
		base64.RawURLEncoding.EncodeToString(u.ServerFingerprint[:]),
		u.Host,
		port,
		base64.RawURLEncoding.EncodeToString(u.SenderID),
		q.Encode(),
	)
}

func parseHostPort(s string) (string, uint16, error) {
	// Handle IPv6-bracket form: [::1]:5223
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return "", 0, errors.New("malformed IPv6 host: missing ']'")
		}
		host := s[1:end]
		rest := s[end+1:]
		port, err := parsePortSuffix(rest)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
	// Plain host[:port]
	colon := strings.LastIndex(s, ":")
	if colon == -1 {
		return s, 5223, nil
	}
	host := s[:colon]
	port, err := strconv.ParseUint(s[colon+1:], 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}
	return host, uint16(port), nil
}

func parsePortSuffix(s string) (uint16, error) {
	if s == "" {
		return 5223, nil
	}
	if !strings.HasPrefix(s, ":") {
		return 0, fmt.Errorf("expected ':' before port, got %q", firstN(s, 8))
	}
	port, err := strconv.ParseUint(s[1:], 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parse port: %w", err)
	}
	return uint16(port), nil
}

func parseVersionRange(s string) (VersionRange, error) {
	dash := strings.Index(s, "-")
	if dash == -1 {
		v, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return VersionRange{}, fmt.Errorf("parse version %q: %w", s, err)
		}
		return VersionRange{Min: Version(v), Max: Version(v)}, nil
	}
	minV, err := strconv.ParseUint(s[:dash], 10, 16)
	if err != nil {
		return VersionRange{}, fmt.Errorf("parse vrange min: %w", err)
	}
	maxV, err := strconv.ParseUint(s[dash+1:], 10, 16)
	if err != nil {
		return VersionRange{}, fmt.Errorf("parse vrange max: %w", err)
	}
	if minV > maxV {
		return VersionRange{}, fmt.Errorf("vrange min %d > max %d", minV, maxV)
	}
	return VersionRange{Min: Version(minV), Max: Version(maxV)}, nil
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ErrBadQueueURI is returned by ParseSMPQueueURI when the input does not
// parse as a valid SMP queue URI.
var ErrBadQueueURI = errors.New("smp: bad queue URI")
