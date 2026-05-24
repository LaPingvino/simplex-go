package smp

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestWord16RoundTrip(t *testing.T) {
	cases := []uint16{0, 1, 255, 256, 0xABCD, math.MaxUint16}
	for _, v := range cases {
		e := NewEncoder()
		e.Word16(v)
		if got := len(e.Bytes()); got != 2 {
			t.Fatalf("Word16(%d) wrote %d bytes, want 2", v, got)
		}
		got, err := NewDecoder(e.Bytes()).Word16()
		if err != nil {
			t.Fatalf("decode Word16(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("Word16 round-trip: got %d want %d", got, v)
		}
	}
}

func TestWord16BigEndian(t *testing.T) {
	e := NewEncoder()
	e.Word16(0xABCD)
	want := []byte{0xAB, 0xCD}
	if !bytes.Equal(e.Bytes(), want) {
		t.Fatalf("Word16 byte order: got %x want %x", e.Bytes(), want)
	}
}

func TestWord32RoundTrip(t *testing.T) {
	cases := []uint32{0, 1, 0xDEADBEEF, math.MaxUint32}
	for _, v := range cases {
		e := NewEncoder()
		e.Word32(v)
		got, err := NewDecoder(e.Bytes()).Word32()
		if err != nil {
			t.Fatalf("decode Word32(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("Word32 round-trip: got %d want %d", got, v)
		}
	}
}

func TestInt64RoundTrip(t *testing.T) {
	cases := []int64{0, 1, -1, math.MinInt64, math.MaxInt64, 0x0123456789ABCDEF}
	for _, v := range cases {
		e := NewEncoder()
		e.Int64(v)
		if got := len(e.Bytes()); got != 8 {
			t.Fatalf("Int64(%d) wrote %d bytes, want 8", v, got)
		}
		got, err := NewDecoder(e.Bytes()).Int64()
		if err != nil {
			t.Fatalf("decode Int64(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("Int64 round-trip: got %d want %d", got, v)
		}
	}
}

func TestInt64HighLowOrder(t *testing.T) {
	// SPEC: Int64 = w32(high) ++ w32(low). 0x0102030405060708 should
	// serialize to 01 02 03 04 05 06 07 08 (high 32 first).
	e := NewEncoder()
	e.Int64(0x0102030405060708)
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(e.Bytes(), want) {
		t.Fatalf("Int64 byte order: got %x want %x", e.Bytes(), want)
	}
}

func TestShortStringRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x42},
		[]byte("hello, smp"),
		bytes.Repeat([]byte{0xAA}, 255),
	}
	for _, v := range cases {
		e := NewEncoder()
		if err := e.ShortString(v); err != nil {
			t.Fatalf("ShortString(len=%d): %v", len(v), err)
		}
		got, err := NewDecoder(e.Bytes()).ShortString()
		if err != nil {
			t.Fatalf("decode ShortString(len=%d): %v", len(v), err)
		}
		if !bytes.Equal(got, v) {
			t.Fatalf("ShortString round-trip: got %x want %x", got, v)
		}
	}
}

func TestShortStringTooLong(t *testing.T) {
	e := NewEncoder()
	err := e.ShortString(bytes.Repeat([]byte{0}, 256))
	if !errors.Is(err, ErrShortStringTooLong) {
		t.Fatalf("ShortString(256): got %v want ErrShortStringTooLong", err)
	}
}

func TestLargeRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{0xAB}, 256),
		bytes.Repeat([]byte{0xCD}, 65535),
	}
	for _, v := range cases {
		e := NewEncoder()
		if err := e.Large(v); err != nil {
			t.Fatalf("Large(len=%d): %v", len(v), err)
		}
		got, err := NewDecoder(e.Bytes()).Large()
		if err != nil {
			t.Fatalf("decode Large(len=%d): %v", len(v), err)
		}
		if !bytes.Equal(got, v) {
			t.Fatalf("Large round-trip mismatch at len=%d", len(v))
		}
	}
}

func TestLargeTooLong(t *testing.T) {
	e := NewEncoder()
	err := e.Large(bytes.Repeat([]byte{0}, 65536))
	if !errors.Is(err, ErrLargeStringTooLong) {
		t.Fatalf("Large(65536): got %v want ErrLargeStringTooLong", err)
	}
}

func TestBoolRoundTrip(t *testing.T) {
	for _, v := range []bool{true, false} {
		e := NewEncoder()
		e.Bool(v)
		if got := len(e.Bytes()); got != 1 {
			t.Fatalf("Bool(%v) wrote %d bytes want 1", v, got)
		}
		got, err := NewDecoder(e.Bytes()).Bool()
		if err != nil {
			t.Fatalf("decode Bool(%v): %v", v, err)
		}
		if got != v {
			t.Fatalf("Bool round-trip: got %v want %v", got, v)
		}
	}
}

func TestBoolExactBytes(t *testing.T) {
	e := NewEncoder()
	e.Bool(true)
	if e.Bytes()[0] != 'T' {
		t.Fatalf("Bool(true): got %q want 'T'", e.Bytes()[0])
	}
	e = NewEncoder()
	e.Bool(false)
	if e.Bytes()[0] != 'F' {
		t.Fatalf("Bool(false): got %q want 'F'", e.Bytes()[0])
	}
}

func TestBoolBadTag(t *testing.T) {
	_, err := NewDecoder([]byte{'X'}).Bool()
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("Bool decode 'X': got %v want ErrBadEncoding", err)
	}
}

func TestTail(t *testing.T) {
	e := NewEncoder()
	e.Word16(0xABCD)
	e.Tail([]byte("rest of the payload"))
	d := NewDecoder(e.Bytes())
	if _, err := d.Word16(); err != nil {
		t.Fatalf("Word16: %v", err)
	}
	if got := d.Tail(); !bytes.Equal(got, []byte("rest of the payload")) {
		t.Fatalf("Tail: got %q", got)
	}
	if !d.Done() {
		t.Fatalf("Tail did not consume rest, %d bytes remaining", d.Remaining())
	}
}

func TestMaybeShortStringPresent(t *testing.T) {
	e := NewEncoder()
	if err := e.MaybeShortString(true, []byte("hello")); err != nil {
		t.Fatalf("MaybeShortString(present): %v", err)
	}
	if e.Bytes()[0] != '1' {
		t.Fatalf("present tag: got %q want '1'", e.Bytes()[0])
	}
	present, v, err := NewDecoder(e.Bytes()).MaybeShortString()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !present || !bytes.Equal(v, []byte("hello")) {
		t.Fatalf("MaybeShortString round-trip: present=%v v=%q", present, v)
	}
}

func TestMaybeShortStringAbsent(t *testing.T) {
	e := NewEncoder()
	if err := e.MaybeShortString(false, nil); err != nil {
		t.Fatalf("MaybeShortString(absent): %v", err)
	}
	if !bytes.Equal(e.Bytes(), []byte{'0'}) {
		t.Fatalf("absent bytes: got %x want '0'", e.Bytes())
	}
	present, v, err := NewDecoder(e.Bytes()).MaybeShortString()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if present || v != nil {
		t.Fatalf("absent round-trip: present=%v v=%v", present, v)
	}
}

func TestMaybeShortStringBadTag(t *testing.T) {
	_, _, err := NewDecoder([]byte{'X'}).MaybeShortString()
	if !errors.Is(err, ErrBadEncoding) {
		t.Fatalf("MaybeShortString 'X' tag: got %v want ErrBadEncoding", err)
	}
}

func TestTruncated(t *testing.T) {
	_, err := NewDecoder([]byte{0xAB}).Word16()
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("Word16 from 1 byte: got %v want ErrTruncated", err)
	}
	_, err = NewDecoder([]byte{0x03, 0x01, 0x02}).ShortString()
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("ShortString claims 3 supplies 2: got %v want ErrTruncated", err)
	}
}

func TestComposite(t *testing.T) {
	e := NewEncoder()
	e.Bool(true)
	e.Word16(42)
	if err := e.ShortString([]byte("queue-id")); err != nil {
		t.Fatal(err)
	}
	if err := e.Large(bytes.Repeat([]byte{0xCD}, 300)); err != nil {
		t.Fatal(err)
	}
	e.Tail([]byte("tail-bytes"))

	d := NewDecoder(e.Bytes())
	if v, _ := d.Bool(); v != true {
		t.Fatal("bool")
	}
	if v, _ := d.Word16(); v != 42 {
		t.Fatal("word16")
	}
	qid, err := d.ShortString()
	if err != nil || string(qid) != "queue-id" {
		t.Fatalf("qid: %q err=%v", qid, err)
	}
	big, err := d.Large()
	if err != nil || len(big) != 300 {
		t.Fatalf("large: len=%d err=%v", len(big), err)
	}
	if !bytes.Equal(d.Tail(), []byte("tail-bytes")) {
		t.Fatal("tail")
	}
}
