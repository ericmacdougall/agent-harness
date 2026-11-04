//go:build windows

package main

import (
	"context"
	"syscall"
	"unsafe"
)

type nativeCredentialVault struct{}

func newCredentialVault() credentialVault  { return nativeCredentialVault{} }
func (nativeCredentialVault) Name() string { return "Windows Credential Manager" }

var credDLL = syscall.NewLazyDLL("advapi32.dll")
var credWrite = credDLL.NewProc("CredWriteW")
var credRead = credDLL.NewProc("CredReadW")
var credDelete = credDLL.NewProc("CredDeleteW")
var credFree = credDLL.NewProc("CredFree")

type windowsCredential struct {
	Flags, Type             uint32
	TargetName, Comment     *uint16
	LastWritten             syscall.Filetime
	BlobSize                uint32
	Blob                    *byte
	Persist, AttributeCount uint32
	Attributes              uintptr
	TargetAlias, UserName   *uint16
}

func (nativeCredentialVault) Available() error {
	if credWrite.Find() != nil || credRead.Find() != nil || credDelete.Find() != nil {
		return errVault
	}
	return nil
}
func credentialTarget(id string) *uint16 {
	v, _ := syscall.UTF16PtrFromString(credentialService + ":" + id)
	return v
}
func (nativeCredentialVault) Put(_ context.Context, id, value string) error {
	if !validVaultItem(id) || !validSecret(value) {
		return errVault
	}
	data := []byte(value)
	c := windowsCredential{Type: 1, TargetName: credentialTarget(id), BlobSize: uint32(len(data)), Blob: &data[0], Persist: 2}
	ok, _, _ := credWrite.Call(uintptr(unsafe.Pointer(&c)), 0)
	if ok == 0 {
		return errVault
	}
	return nil
}
func (nativeCredentialVault) Get(_ context.Context, id string) (string, error) {
	if !validVaultItem(id) {
		return "", errVault
	}
	var c *windowsCredential
	ok, _, _ := credRead.Call(uintptr(unsafe.Pointer(credentialTarget(id))), 1, 0, uintptr(unsafe.Pointer(&c)))
	if ok == 0 {
		return "", errVault
	}
	defer credFree.Call(uintptr(unsafe.Pointer(c)))
	if c.BlobSize > 8192 {
		return "", errVault
	}
	return string(unsafe.Slice(c.Blob, int(c.BlobSize))), nil
}
func (nativeCredentialVault) Delete(_ context.Context, id string) error {
	if !validVaultItem(id) {
		return errVault
	}
	ok, _, _ := credDelete.Call(uintptr(unsafe.Pointer(credentialTarget(id))), 1, 0)
	if ok == 0 {
		return errVault
	}
	return nil
}
