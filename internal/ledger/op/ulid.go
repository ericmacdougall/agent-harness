package op

import (
	"crypto/rand"
	"errors"
	"strings"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Id prefixes. Every ledger identifier is <prefix><26-char ULID>.
const (
	PrefixOp      = "op_"
	PrefixProject = "proj_"
	PrefixWriter  = "w_"
	PrefixTicket  = "tk_"
	PrefixComment = "c_"
)

// NewULID returns a ULID whose 48-bit time component is ms and whose 80 random bits come from crypto/rand.
func NewULID(ms int64) (string, error) {
	if ms < 0 || ms >= 1<<48 {
		return "", errors.New("ulid: time out of range")
	}
	var b [16]byte
	for i := 0; i < 6; i++ {
		b[i] = byte(uint64(ms) >> (40 - 8*i))
	}
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	return encodeULID(b), nil
}

func encodeULID(b [16]byte) string {
	// 128 bits -> 26 base32 chars; the first char carries the top 3 bits.
	var out [26]byte
	var acc uint64
	// Process as a big number: simple bit reader.
	bit := func(i int) uint64 { return uint64(b[i/8]>>(7-i%8)) & 1 }
	pos := -2 // 130 bits with 2 leading zero bits
	for c := 0; c < 26; c++ {
		acc = 0
		for k := 0; k < 5; k++ {
			acc <<= 1
			if pos >= 0 {
				acc |= bit(pos)
			}
			pos++
		}
		out[c] = crockford[acc]
	}
	return string(out[:])
}

// ValidULID reports whether s is a canonical uppercase Crockford ULID (26 chars, first char <= '7').
func ValidULID(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}

// ULIDTime returns the millisecond timestamp of a valid ULID.
func ULIDTime(s string) int64 {
	var ms int64
	for i := 0; i < 10; i++ {
		ms = ms<<5 | int64(strings.IndexByte(crockford, s[i]))
	}
	return ms
}

// ValidID reports whether s is prefix + ULID.
func ValidID(s, prefix string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	return ok && ValidULID(rest)
}

// NewID mints prefix + ULID at ms.
func NewID(prefix string, ms int64) (string, error) {
	u, err := NewULID(ms)
	if err != nil {
		return "", err
	}
	return prefix + u, nil
}
