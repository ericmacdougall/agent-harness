package op

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Field is one member of an ordered JSON object.
type Field struct {
	K string
	V any
}

// Obj is a JSON object whose members are written in slice order. Op bytes and every --json rendering
// use it so field order is part of the contract and never depends on map iteration.
type Obj []Field

// Encode writes v as compact JSON with Python ensure_ascii escaping (every byte outside 0x20..0x7e is
// escaped), so stored ops and machine output are inert in any terminal.
// Supported: nil, bool, string, int, int64, uint64, json.Number, []any, []string, []Obj, Obj,
// map[string]any (sorted keys), json.RawMessage (validated, re-encoded).
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MustEncode is Encode for values built by this package; a failure is a programming error.
func MustEncode(v any) []byte {
	out, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return out
}

var errUnsupported = errors.New("ojson: unsupported value")

func encode(b *bytes.Buffer, v any) error {
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
			return fmt.Errorf("%w: invalid UTF-8", errUnsupported)
		}
		writeString(b, x)
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case json.Number:
		if _, err := strconv.ParseInt(string(x), 10, 64); err != nil {
			return fmt.Errorf("%w: non-integer number %q", errUnsupported, string(x))
		}
		b.WriteString(string(x))
	case []string:
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
	case []Obj:
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
	case Obj:
		b.WriteByte('{')
		for i, f := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, f.K); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := encode(b, f.V); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		o := make(Obj, 0, len(keys))
		for _, k := range keys {
			o = append(o, Field{k, x[k]})
		}
		return encode(b, o)
	case json.RawMessage:
		parsed, err := DecodeStrict(x)
		if err != nil {
			return err
		}
		return encode(b, parsed)
	default:
		return fmt.Errorf("%w: %T", errUnsupported, v)
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
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

// DecodeStrict parses one JSON value into Obj (member order kept), []any, string, json.Number, bool or
// nil. It rejects duplicate keys, trailing data, invalid UTF-8 and nesting deeper than 32, so a value
// has exactly one meaning for every reader.
func DecodeStrict(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("json: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("json: trailing data")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("json: nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := Obj{}
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("json: %w", err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("json: object key is not a string")
				}
				if seen[k] {
					return nil, fmt.Errorf("json: duplicate key %q", k)
				}
				seen[k] = true
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				o = append(o, Field{k, v})
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("json: %w", err)
			}
			return o, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("json: %w", err)
			}
			return a, nil
		}
		return nil, errors.New("json: unexpected delimiter")
	default:
		return t, nil
	}
}

// Get returns the member named k.
func (o Obj) Get(k string) (any, bool) {
	for _, f := range o {
		if f.K == k {
			return f.V, true
		}
	}
	return nil, false
}

// Keys lists member names in order.
func (o Obj) Keys() []string {
	ks := make([]string, len(o))
	for i, f := range o {
		ks[i] = f.K
	}
	return ks
}
