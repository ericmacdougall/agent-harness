package main

import (
	"strings"
)

type literalStream struct {
	values  []string
	pending string
	keep    int
}

func (f *literalStream) Push(value string) string {
	f.pending += value
	cut := len(f.pending) - f.keep
	if cut <= 0 {
		return ""
	}
	// Never cut through a known secret occurrence.
	for _, secret := range f.values {
		start := 0
		for {
			at := strings.Index(f.pending[start:], secret)
			if at < 0 {
				break
			}
			at += start
			if at < cut && at+len(secret) > cut {
				cut = at
			}
			start = at + len(secret)
			if start >= len(f.pending) {
				break
			}
		}
	}
	result := f.pending[:cut]
	f.pending = f.pending[cut:]
	for _, secret := range f.values {
		result = strings.ReplaceAll(result, secret, "[REDACTED]")
	}
	return result
}
func (f *literalStream) Flush() string {
	result := f.pending
	f.pending = ""
	for _, secret := range f.values {
		result = strings.ReplaceAll(result, secret, "[REDACTED]")
	}
	return result
}

type combinedStream struct {
	first  streamRedactor
	second streamRedactor
}

func (f combinedStream) Push(value string) string { return f.second.Push(f.first.Push(value)) }
func (f combinedStream) Flush() string            { return f.second.Push(f.first.Flush()) + f.second.Flush() }
func (a *app) rememberCapability(value string) {
	a.coreSecretMu.Lock()
	defer a.coreSecretMu.Unlock()
	a.coreSecrets = append(a.coreSecrets, value)
}
func (a *app) streamFilter() streamRedactor {
	a.coreSecretMu.Lock()
	values := append([]string{}, a.coreSecrets...)
	a.coreSecretMu.Unlock()
	keep := 0
	for _, v := range values {
		if len(v) > keep {
			keep = len(v)
		}
	}
	if keep > 0 {
		keep--
	}
	return combinedStream{first: a.newRedactor(), second: &literalStream{values: values, keep: keep}}
}
func (a *app) cleanValue(value any) any {
	switch v := value.(type) {
	case string:
		return a.clean(v)
	case []any:
		for i, item := range v {
			v[i] = a.cleanValue(item)
		}
		return v
	case map[string]any:
		for k, item := range v {
			v[k] = a.cleanValue(item)
		}
		return v
	}
	return value
}
func (a *app) cleanStructured(value []any) []any {
	if value == nil {
		return nil
	}
	result, _ := a.cleanValue(value).([]any)
	return result
}
