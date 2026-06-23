package lore

import (
	"bytes"
	"testing"

	modelv1 "arcloreweb/gen/lore/model/v1"
)

func TestIDHexRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		id   [16]byte
		hex  string
	}{
		{
			name: "zero",
			id:   [16]byte{},
			hex:  "00000000000000000000000000000000",
		},
		{
			name: "all-ff",
			id:   [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			hex:  "ffffffffffffffffffffffffffffffff",
		},
		{
			name: "sequential",
			id:   [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			hex:  "000102030405060708090a0b0c0d0e0f",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IDToHex(tc.id)
			if got != tc.hex {
				t.Fatalf("IDToHex = %q, want %q", got, tc.hex)
			}
			parsed, err := ParseID(tc.hex)
			if err != nil {
				t.Fatalf("ParseID(%q) error: %v", tc.hex, err)
			}
			if parsed != tc.id {
				t.Fatalf("ParseID round-trip = %v, want %v", parsed, tc.id)
			}
		})
	}
}

func TestParseIDRejectsBadInput(t *testing.T) {
	if _, err := ParseID("tooshort"); err == nil {
		t.Fatal("expected error for short id")
	}
	if _, err := ParseID("zz000000000000000000000000000000"); err == nil {
		t.Fatal("expected error for non-hex id")
	}
}

func fill(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func seq(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func TestAddressRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr *modelv1.Address
		str  string
	}{
		{
			name: "zero",
			addr: &modelv1.Address{Hash: fill(32, 0x00), Context: fill(16, 0x00)},
			str: "0000000000000000000000000000000000000000000000000000000000000000" +
				"-00000000000000000000000000000000",
		},
		{
			name: "all-ff",
			addr: &modelv1.Address{Hash: fill(32, 0xff), Context: fill(16, 0xff)},
			str: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
				"-ffffffffffffffffffffffffffffffff",
		},
		{
			name: "sequential",
			addr: &modelv1.Address{Hash: seq(32), Context: seq(16)},
			str: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"-000102030405060708090a0b0c0d0e0f",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.str) != 97 {
				t.Fatalf("test string length = %d, want 97", len(tc.str))
			}
			got, err := AddressString(tc.addr)
			if err != nil {
				t.Fatalf("AddressString error: %v", err)
			}
			if got != tc.str {
				t.Fatalf("AddressString = %q, want %q", got, tc.str)
			}
			parsed, err := ParseAddress(tc.str)
			if err != nil {
				t.Fatalf("ParseAddress error: %v", err)
			}
			if !bytes.Equal(parsed.Hash, tc.addr.Hash) {
				t.Fatalf("ParseAddress hash = %x, want %x", parsed.Hash, tc.addr.Hash)
			}
			if !bytes.Equal(parsed.Context, tc.addr.Context) {
				t.Fatalf("ParseAddress context = %x, want %x", parsed.Context, tc.addr.Context)
			}
		})
	}
}

func TestParseAddressRejectsBadInput(t *testing.T) {
	if _, err := ParseAddress("tooshort"); err == nil {
		t.Fatal("expected error for short address")
	}
	// 97 chars but separator in the wrong place (extra hex before the dash).
	bad := fill(33, 'a')
	badStr := string(bad) + "-" + string(fill(63, 'b'))
	if len(badStr) != 97 {
		t.Fatalf("setup: badStr len = %d", len(badStr))
	}
	if _, err := ParseAddress(badStr); err == nil {
		t.Fatal("expected error for misplaced separator")
	}
}

func TestAddressBytesRoundTrip(t *testing.T) {
	addr := &modelv1.Address{Hash: seq(32), Context: seq(16)}
	raw, err := AddressBytes(addr)
	if err != nil {
		t.Fatalf("AddressBytes error: %v", err)
	}
	if len(raw) != 48 {
		t.Fatalf("AddressBytes len = %d, want 48", len(raw))
	}
	if !bytes.Equal(raw[:32], addr.Hash) || !bytes.Equal(raw[32:], addr.Context) {
		t.Fatalf("AddressBytes layout mismatch")
	}
}
