package store

import (
	"os"
	"strings"
	"testing"
)

func envValue(env []string, prefix string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

func configValues(env []string, key string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_KEY_") && strings.HasSuffix(e, "="+key) {
			n := strings.TrimSuffix(strings.TrimPrefix(e, "GIT_CONFIG_KEY_"), "="+key)
			for _, v := range env {
				if v == "" || !strings.HasPrefix(v, "GIT_CONFIG_VALUE_"+n+"=") {
					continue
				}
				out = append(out, strings.TrimPrefix(v, "GIT_CONFIG_VALUE_"+n+"="))
			}
		}
	}
	return out
}

func TestSafeHelpersKeepsOnlyNamedOrAbsoluteNoArguments(t *testing.T) {
	in := []string{"osxkeychain", "store", "cache", "manager", "/usr/local/bin/git-credential-foo", "!sh -c id", "store --file=/x", "cache --timeout 9",
		"../rel/helper", "", "a b", "-x", "helper;rm", "$(id)", "/bin/sh -c id", "/path with space/h"}
	got := SafeHelpers(in)
	want := []string{"osxkeychain", "store", "cache", "manager", "/usr/local/bin/git-credential-foo"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTransportEnvHasNoCredentialHelperUnlessGiven(t *testing.T) {
	if vals := configValues(TransportEnv(), "credential.helper"); len(vals) != 0 && !(len(vals) == 1 && vals[0] == "") {
		t.Fatalf("default transport env has helpers: %v", vals)
	}
	env := TransportEnvWith([]string{"osxkeychain", "!evil"})
	vals := configValues(env, "credential.helper")
	if strings.Join(vals, "|") != "|osxkeychain" && !(len(vals) >= 2 && vals[len(vals)-1] == "osxkeychain") {
		t.Fatalf("helpers: %v", vals)
	}
	for _, v := range vals {
		if strings.Contains(v, "!") {
			t.Fatalf("an unsafe helper reached the environment: %v", vals)
		}
	}
	if envValue(env, "GIT_TERMINAL_PROMPT=0") == nil || envValue(env, "GIT_ALLOW_PROTOCOL=ssh:https:file") == nil {
		t.Fatalf("prompts or protocol allowlist lost")
	}
	_ = os.Getenv
}
