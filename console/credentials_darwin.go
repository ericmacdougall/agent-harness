//go:build darwin

package main

import (
	"context"
	"os"
	"strings"
)

type nativeCredentialVault struct{}

func newCredentialVault() credentialVault  { return nativeCredentialVault{} }
func (nativeCredentialVault) Name() string { return "macOS Keychain" }
func (nativeCredentialVault) Available() error {
	if _, e := os.Stat("/usr/bin/security"); e != nil {
		return errVault
	}
	return nil
}
func (nativeCredentialVault) Put(ctx context.Context, id, value string) error {
	if !validVaultItem(id) || !validSecret(value) {
		return errVault
	}
	// -w must remain LAST: security prompts twice and reads stdin. No shell/-i,
	// unrestricted access (-A), update (-U), or secret-bearing command argument.
	_, e := credentialCommand(ctx, "/usr/bin/security", []string{"add-generic-password", "-a", id, "-s", credentialService, "-w"}, value+"\n"+value+"\n")
	return e
}
func (nativeCredentialVault) Get(ctx context.Context, id string) (string, error) {
	if !validVaultItem(id) {
		return "", errVault
	}
	v, e := credentialCommand(ctx, "/usr/bin/security", []string{"find-generic-password", "-a", id, "-s", credentialService, "-w"}, "")
	return strings.TrimSuffix(v, "\n"), e
}
func (nativeCredentialVault) Delete(ctx context.Context, id string) error {
	if !validVaultItem(id) {
		return errVault
	}
	_, e := credentialCommand(ctx, "/usr/bin/security", []string{"delete-generic-password", "-a", id, "-s", credentialService}, "")
	return e
}
