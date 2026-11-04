//go:build !darwin && !linux && !windows

package main

import "context"

type nativeCredentialVault struct{}

func newCredentialVault() credentialVault                                 { return nativeCredentialVault{} }
func (nativeCredentialVault) Name() string                                { return "unsupported operating system" }
func (nativeCredentialVault) Available() error                            { return errVault }
func (nativeCredentialVault) Put(context.Context, string, string) error   { return errVault }
func (nativeCredentialVault) Get(context.Context, string) (string, error) { return "", errVault }
func (nativeCredentialVault) Delete(context.Context, string) error        { return errVault }
