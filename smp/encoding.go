package smp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire-encoding primitives mirroring Simplex.Messaging.Encoding (Haskell).
// Ref: simplexmq/src/Simplex/Messaging/Encoding.hs.

const (
	maxShortString = 255   // 1-byte length prefix
	maxLargeString = 65535 // 2-byte BE length prefix
)

// Encoder builds an SMP payload by appending primitives in order.
type Encoder struct{ buf []byte }

func NewEncoder() *Encoder      { return &Encoder{} }
func (e *Encoder) Bytes() []byte { return e.buf }
func (e *Encoder) Len() int      { return len(e.buf) }

func (e *Encoder) Word16(v uint16) { e.buf = binary.BigEndian.AppendUint16(e.buf, v) }
func (e *Encoder) Word32(v uint32) { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }

// Int64 is encoded as two BE Word32s: high 32 bits, then low 32 bits.
// SPEC: Encoding Int64 instance — `smpEncode i = w32 (i \`shiftR\` 32) <> w32 i`.
func (e *Encoder) Int64(v int64) {
	e.Word32(uint32(uint64(v) >> 32))
	e.Word32(uint32(uint64(v)))
}

// ShortString appends a 1-byte length followed by v. Returns ErrShortStringTooLong
// if len(v) > 255. Mirrors Haskell `instance Encoding ByteString`.
func (e *Encoder) ShortString(v []byte) error {
	if len(v) > maxShortString {
		return fmt.Errorf("%w: %d bytes", ErrShortStringTooLong, len(v))
	}
	e.buf = append(e.buf, byte(len(v)))
	e.buf = append(e.buf, v...)
	return nil
}

// Large appends a 2-byte BE length followed by v. Returns ErrLargeStringTooLong
// if len(v) > 65535. Mirrors Haskell `instance Encoding Large`.
func (e *Encoder) Large(v []byte) error {
	if len(v) > maxLargeString {
		return fmt.Errorf("%w: %d bytes", ErrLargeStringTooLong, len(v))
	}
	e.Word16(uint16(len(v)))
	e.buf = append(e.buf, v...)
	return nil
}

// Bool appends 'T' or 'F'.
func (e *Encoder) Bool(v bool) {
	if v {
		e.buf = append(e.buf, 'T')
	} else {
		e.buf = append(e.buf, 'F')
	}
}

func (e *Encoder) Char(c byte) { e.buf = append(e.buf, c) }

// Tail appends bytes verbatim. Must be the last field in a transmission since
// the receiver consumes to end-of-input.
func (e *Encoder) Tail(v []byte) { e.buf = append(e.buf, v...) }

// MaybeShortString appends '0' (absent) or '1' followed by ShortString(v).
// Mirrors Haskell `instance Encoding a => Encoding (Maybe a)` specialized to
// ByteString. Most SMP Maybe fields are short strings (basicAuth, etc.); add
// other-typed Maybe helpers when a command actually needs them.
func (e *Encoder) MaybeShortString(present bool, v []byte) error {
	if !present {
		e.buf = append(e.buf, '0')
		return nil
	}
	e.buf = append(e.buf, '1')
	return e.ShortString(v)
}

// Raw appends bytes verbatim, no length prefix or framing. Useful for fields
// whose length is supplied separately, or for composing the wire output of a
// sub-encoder.
func (e *Encoder) Raw(v []byte) { e.buf = append(e.buf, v...) }

// Decoder reads SMP primitives sequentially from a byte buffer.
type Decoder struct {
	buf []byte
	pos int
}

func NewDecoder(buf []byte) *Decoder { return &Decoder{buf: buf} }

func (d *Decoder) Remaining() int { return len(d.buf) - d.pos }
func (d *Decoder) Done() bool     { return d.pos >= len(d.buf) }

func (d *Decoder) need(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.buf) {
		return nil, fmt.Errorf("%w: need %d, have %d", ErrTruncated, n, len(d.buf)-d.pos)
	}
	out := d.buf[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *Decoder) Word16() (uint16, error) {
	b, err := d.need(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (d *Decoder) Word32() (uint32, error) {
	b, err := d.need(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *Decoder) Int64() (int64, error) {
	hi, err := d.Word32()
	if err != nil {
		return 0, err
	}
	lo, err := d.Word32()
	if err != nil {
		return 0, err
	}
	return int64(uint64(hi)<<32 | uint64(lo)), nil
}

func (d *Decoder) ShortString() ([]byte, error) {
	lb, err := d.need(1)
	if err != nil {
		return nil, err
	}
	return d.need(int(lb[0]))
}

func (d *Decoder) Large() ([]byte, error) {
	n, err := d.Word16()
	if err != nil {
		return nil, err
	}
	return d.need(int(n))
}

func (d *Decoder) Bool() (bool, error) {
	b, err := d.need(1)
	if err != nil {
		return false, err
	}
	switch b[0] {
	case 'T':
		return true, nil
	case 'F':
		return false, nil
	default:
		return false, fmt.Errorf("%w: expected T/F, got %q", ErrBadEncoding, b[0])
	}
}

func (d *Decoder) Char() (byte, error) {
	b, err := d.need(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// Tail consumes the remainder of the buffer.
func (d *Decoder) Tail() []byte {
	out := d.buf[d.pos:]
	d.pos = len(d.buf)
	return out
}

func (d *Decoder) MaybeShortString() (present bool, v []byte, err error) {
	tag, err := d.Char()
	if err != nil {
		return false, nil, err
	}
	switch tag {
	case '0':
		return false, nil, nil
	case '1':
		v, err = d.ShortString()
		return true, v, err
	default:
		return false, nil, fmt.Errorf("%w: expected '0'/'1' Maybe tag, got %q", ErrBadEncoding, tag)
	}
}

var (
	ErrShortStringTooLong = errors.New("smp: short string exceeds 255 bytes")
	ErrLargeStringTooLong = errors.New("smp: large string exceeds 65535 bytes")
	ErrTruncated          = errors.New("smp: truncated input")
	ErrBadEncoding        = errors.New("smp: bad encoding")
)
