//go:build !ledgertest

package writer

// TestBuild is false in every binary built without -tags ledgertest, including plain `go build` and
// `go install`, so the HARNESS_LEDGER_FAKE_*/TEST_* variables are refused there.
const TestBuild = false
