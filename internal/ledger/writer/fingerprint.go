// Package writer resolves which writer id this process appends as. A writer identifies a machine plus a
// git common dir: fingerprint = sha256(sha256(machine_id) || inode(common_dir)). writer.json maps every
// fingerprint ever seen to its writer, so alternating hosts over one checkout reuse their writers instead
// of minting new ones, and writers are never removed.
package writer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// FakeMachineIDEnv overrides the machine id in development builds (tests only).
const FakeMachineIDEnv = "HARNESS_LEDGER_FAKE_MACHINE_ID"

// TestHooksAllowed is set by the binary: true only for development builds. Release builds refuse the
// fake-clock and fake-machine-id variables.
var TestHooksAllowed = false

// ErrTestHookInRelease is returned when a test-only variable is set in a release build.
var ErrTestHookInRelease = errors.New("test-only HARNESS_LEDGER_FAKE_* variable set in a release build")

// MachineID returns sha256 of the platform machine id (the raw value is never stored or printed).
func MachineID() (string, error) {
	if v, ok := os.LookupEnv(FakeMachineIDEnv); ok {
		if !TestHooksAllowed {
			return "", ErrTestHookInRelease
		}
		return hashHex(v), nil
	}
	raw, err := platformMachineID()
	if err != nil {
		return "", err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("machine id is empty")
	}
	return hashHex(raw), nil
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func platformMachineID() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", errors.New("ioreg failed")
		}
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, `"IOPlatformUUID"`) {
				if _, v, ok := strings.Cut(l, "="); ok {
					return strings.Trim(strings.TrimSpace(v), `"`), nil
				}
			}
		}
		return "", errors.New("IOPlatformUUID not found")
	case "windows":
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		out, err := exec.Command(sysroot+`\System32\reg.exe`, "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err != nil {
			return "", errors.New("reg query MachineGuid failed")
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) == 3 && f[0] == "MachineGuid" {
				return f[2], nil
			}
		}
		return "", errors.New("MachineGuid not found")
	default:
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
				return string(b), nil
			}
		}
		return "", errors.New("no machine id (/etc/machine-id)")
	}
}

// Fingerprint combines the machine id hash with the inode of the common dir.
func Fingerprint(machineIDHash string, commonDirInode uint64) string {
	var ino [8]byte
	binary.BigEndian.PutUint64(ino[:], commonDirInode)
	sum := sha256.Sum256(append([]byte(machineIDHash), ino[:]...))
	return hex.EncodeToString(sum[:])
}
