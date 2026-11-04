package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCredentialStreamingEverySplitAndOverlap(t *testing.T) {
	secret := "SYNTHETIC-SECRET-ABCDE"
	input := "before " + secret + " after"
	for split := 0; split <= len(input); split++ {
		s := makeSecretStream([]string{secret})
		got := s.Push(input[:split]) + s.Push(input[split:]) + s.Flush()
		if got != "before [REDACTED] after" {
			t.Fatalf("split %d leaked or corrupted text: %q", split, got)
		}
	}
	s := makeSecretStream([]string{"abc", "abcd", "猫鍵"})
	got := ""
	for _, b := range []byte("abcd猫鍵 ok") {
		got += s.Push(string([]byte{b}))
	}
	got += s.Flush()
	if got != "[REDACTED][REDACTED] ok" {
		t.Fatal("overlap/unicode mismatch", got)
	}
	// Whole-chunk replacement reproduces the original failure control.
	half := len(secret) / 2
	unsafe := strings.ReplaceAll(secret[:half], secret, "[REDACTED]") + strings.ReplaceAll(secret[half:], secret, "[REDACTED]")
	if unsafe != secret {
		t.Fatal("negative control failed to reproduce risk")
	}
}
func TestCredentialNativeSyntheticRoundtrip(t *testing.T) {
	if os.Getenv("HARNESS_TEST_NATIVE_VAULT") != "1" {
		t.Skip("explicit opt-in required for disposable native vault test")
	}
	v := newCredentialVault()
	if e := v.Available(); e != nil {
		t.Fatal(e)
	}
	id := freshID()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	defer v.Delete(context.Background(), id)
	secret := "SYNTHETIC-NATIVE-" + freshID()
	if e := v.Put(ctx, id, secret); e != nil {
		t.Fatal(e)
	}
	got, e := v.Get(ctx, id)
	if e != nil || got != secret {
		t.Fatal("native synthetic roundtrip failed")
	}
	if e = v.Delete(ctx, id); e != nil {
		t.Fatal(e)
	}
}
