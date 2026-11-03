//go:build linux

package main

import (
	"context"
	"os/exec"
	"strings"
)

type nativeCredentialVault struct{}

func newCredentialVault() credentialVault  { return nativeCredentialVault{} }
func (nativeCredentialVault) Name() string { return "Secret Service (secret-tool)" }
func (nativeCredentialVault) Available() error {
	if _, e := exec.LookPath("secret-tool"); e != nil {
		return errVault
	}
	return nil
}
func (nativeCredentialVault) Put(ctx context.Context, id, value string) error {
	if !validVaultItem(id) || !validSecret(value) {
		return errVault
	}
	p, e := exec.LookPath("secret-tool")
	if e != nil {
		return errVault
	}
	_, e = credentialCommand(ctx, p, []string{"store", "--label=Agent Harness Console", "service", credentialService, "account", id}, value)
	return e
}
func (nativeCredentialVault) Get(ctx context.Context, id string) (string, error) {
	if !validVaultItem(id) {
		return "", errVault
	}
	p, e := exec.LookPath("secret-tool")
	if e != nil {
		return "", errVault
	}
	v, e := credentialCommand(ctx, p, []string{"lookup", "service", credentialService, "account", id}, "")
	return strings.TrimSuffix(v, "\n"), e
}
func (nativeCredentialVault) Delete(ctx context.Context, id string) error {
	if !validVaultItem(id) {
		return errVault
	}
	p, e := exec.LookPath("secret-tool")
	if e != nil {
		return errVault
	}
	_, e = credentialCommand(ctx, p, []string{"clear", "service", credentialService, "account", id}, "")
	return e
}
