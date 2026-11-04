// Package pycompat reproduces Python json.dumps output byte for byte for the shapes the harness writes.
//
// Canonical mirrors json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False),
// the encoding used for digests and subjects. Go's encoding/json differs: it escapes <, >, & and U+2028/9,
// sorts nothing for structs, and formats floats differently, so it must never feed a hash.
package pycompat

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrUnsupported reports a value Python's encoder would reject (NaN/Inf with allow_nan=False) or a type
// outside the JSON data model.
var ErrUnsupported = errors.New("pycompat: unsupported value")

// Canonical encodes v. Supported: nil, bool, string, int/int64/uint64, float64, []any, map[string]any.
func Canonical(v any) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: invalid UTF-8 string", ErrUnsupported)
		}
		writeString(b, x)
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case float64:
		s, err := FloatRepr(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Python sorts str keys by code point; Go compares UTF-8 bytes, which orders code points identically.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if !utf8.ValidString(k) {
				return fmt.Errorf("%w: invalid UTF-8 key", ErrUnsupported)
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := encode(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
	return nil
}

// writeString matches CPython's ensure_ascii escaping: the short escapes \" \\ \n \r \t \b \f, every other
// code point below 0x20 or above 0x7e as \uXXXX (lowercase hex), astral code points as surrogate pairs.
// Note that 0x7f (DEL) is escaped too, which Go's encoder does not do.
func writeString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	u := func(r rune) {
		b.WriteString(`\u`)
		b.WriteByte(hex[r>>12&0xf])
		b.WriteByte(hex[r>>8&0xf])
		b.WriteByte(hex[r>>4&0xf])
		b.WriteByte(hex[r&0xf])
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				b.WriteRune(r)
			case r > 0xffff:
				r1, r2 := utf16.EncodeRune(r)
				u(r1)
				u(r2)
			default:
				u(r)
			}
		}
	}
	b.WriteByte('"')
}

// FloatRepr returns Python's float.__repr__: the shortest round-trip digits, scientific notation when the
// decimal exponent is < -4 or >= 16, a trailing ".0" for integral values, and "e+XX"/"e-XX" with at least
// two exponent digits.
func FloatRepr(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %v is not JSON compliant", ErrUnsupported, f)
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0", nil
		}
		return "0.0", nil
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX, shortest digits
	mant, expS, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es = "-"
			exp = -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, es, exp), nil
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + digits, nil
	}
	if len(digits) <= exp+1 {
		return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0", nil
	}
	return sign + digits[:exp+1] + "." + digits[exp+1:], nil
}
