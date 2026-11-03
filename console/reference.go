package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"
	"unicode/utf8"
)

type reference struct {
	Schema     int    `json:"schema"`
	Client     string `json:"client"`
	CapturedAt string `json:"captured_at"`
	Title      string `json:"title"`
	Kind       string `json:"kind"`
	Body       string `json:"body"`
	Truncated  bool   `json:"truncated"`
	SessionID  string `json:"session_id,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
}

func validJSONUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		code, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func parseReference(data []byte) (*reference, error) {
	if len(data) > 256<<10 || !validJSONUnicode(data) {
		return nil, errors.New("invalid reference encoding or size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, e := decoder.Token()
	if e != nil || first != json.Delim('{') {
		return nil, errors.New("reference must be an object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, e := decoder.Token()
		if e != nil {
			return nil, e
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid reference field")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errors.New("duplicate reference field")
		}
		var raw json.RawMessage
		if e = decoder.Decode(&raw); e != nil {
			return nil, e
		}
		fields[name] = raw
	}
	if _, e = decoder.Token(); e != nil {
		return nil, e
	}
	if _, e = decoder.Token(); e != io.EOF {
		return nil, errors.New("extra data after reference")
	}
	for _, key := range []string{"schema", "client", "captured_at", "title", "kind", "body", "truncated"} {
		if _, ok := fields[key]; !ok {
			return nil, errors.New("missing reference field")
		}
	}
	for key, raw := range fields {
		if key == "schema" {
			continue
		}
		if key == "truncated" {
			trimmed := bytes.TrimSpace(raw)
			if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
				return nil, errors.New("truncated must be a boolean")
			}
		} else if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '"' {
			return nil, errors.New("reference metadata must be strings")
		}
	}
	clean, e := json.Marshal(fields)
	if e != nil {
		return nil, e
	}
	strict := json.NewDecoder(bytes.NewReader(clean))
	strict.DisallowUnknownFields()
	var value reference
	if e = strict.Decode(&value); e != nil {
		return nil, e
	}
	if value.Schema != 1 || !bytes.Equal(bytes.TrimSpace(fields["schema"]), []byte("1")) {
		return nil, errors.New("unsupported reference schema")
	}
	if value.Client == "" || len([]rune(value.Client)) > 64 || value.Title == "" || len([]rune(value.Title)) > 512 || value.Body == "" || len(value.Body) > 128<<10 || len([]rune(value.SessionID)) > 128 || len([]rune(value.SourceURL)) > 2048 {
		return nil, errors.New("reference metadata or body exceeds its bound")
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|\+00:00)$`).MatchString(value.CapturedAt) {
		return nil, errors.New("reference capture time must be UTC RFC3339")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.CapturedAt); err != nil {
		return nil, errors.New("invalid capture time")
	}
	if value.Kind != "summary" && value.Kind != "excerpt" && value.Kind != "transcript" {
		return nil, errors.New("invalid reference kind")
	}
	return &value, nil
}
func loadReference(path, digest string) (*reference, error) {
	if path == "" && digest == "" {
		return nil, nil
	}
	if path == "" || len(digest) != 64 {
		return nil, errors.New("reference file and SHA-256 must be supplied together")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("reference must be a regular private file")
	}
	parent, e := os.Lstat(filepath.Dir(path))
	if e != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("reference directory must be private and real")
	}
	if runtime.GOOS != "windows" && (info.Mode().Perm() != 0600 || parent.Mode().Perm() != 0700) {
		return nil, errors.New("reference file requires mode0600 and directory0700")
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	opened, e := file.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errors.New("reference file changed during open")
	}
	data, e := io.ReadAll(io.LimitReader(file, 256<<10+1))
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("reference digest does not match")
	}
	return parseReference(data)
}
