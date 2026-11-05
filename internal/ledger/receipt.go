package ledger

// The GoodQA receipt (goodqa-ledger-receipt/v1) and its optional ed25519 signed envelope.
//
// Signed envelope (what GoodQA returns when it signs):
//   {"format":"goodqa-ledger-receipt-signed/v1","receipt":{...},"alg":"ed25519",
//    "key_id":"<first 16 hex of sha256(raw 32-byte public key)>","sig":"<base64url, no padding, 64 bytes>"}
// The signature covers the ASCII tag "goodqa-ledger-receipt/v1\n" followed by the canonical receipt: compact
// JSON, keys sorted at every level, separators (',', ':'), ASCII only, integers as plain digits, no trailing
// newline (Python: json.dumps(r, sort_keys=True, separators=(',', ':'), ensure_ascii=True)). import_id is
// restricted to [A-Za-z0-9._:-] so Go and Python produce identical bytes. The public key is 32 raw bytes given
// as hex, base64 or PEM SPKI in a file the user pins with `bind --goodqa-key`.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
)

// Receipt and envelope format names and the signing tag.
const (
	SignedReceiptFormat = "goodqa-ledger-receipt-signed/v1"
	signTag             = "goodqa-ledger-receipt/v1\n"
)

// ReceiptFrontier is one writer's frontier in a receipt.
type ReceiptFrontier struct {
	Writer string `json:"writer"`
	Ops    int    `json:"ops"`
	WallMs int64  `json:"wall_ms"`
	Ctr    int64  `json:"ctr"`
	LastOp string `json:"last_op"`
}

// ReceiptTicket maps a ledger handle to a GoodQA issue number.
type ReceiptTicket struct {
	Handle string `json:"handle"`
	Number int    `json:"number"`
}

// ReceiptDoc is the receipt document.
type ReceiptDoc struct {
	Format        string            `json:"format"`
	GoodQAProject string            `json:"goodqa_project"`
	ImportID      string            `json:"import_id"`
	LedgerProject string            `json:"ledger_project"`
	ExportDigest  string            `json:"export_digest"`
	BaseDigest    string            `json:"base_digest"`
	Redacted      *bool             `json:"redacted"`
	Frontier      []ReceiptFrontier `json:"frontier"`
	Tickets       []ReceiptTicket   `json:"tickets"`
	ImportedMs    int64             `json:"imported_at_ms"`
}

// Canonical returns the receipt's canonical bytes (see the file comment).
func (r *ReceiptDoc) Canonical() ([]byte, error) {
	red := false
	if r.Redacted != nil {
		red = *r.Redacted
	}
	fr := []any{}
	for _, f := range r.Frontier {
		fr = append(fr, map[string]any{"writer": f.Writer, "ops": f.Ops, "wall_ms": f.WallMs, "ctr": f.Ctr, "last_op": f.LastOp})
	}
	tk := []any{}
	for _, t := range r.Tickets {
		tk = append(tk, map[string]any{"handle": t.Handle, "number": t.Number})
	}
	doc := map[string]any{"format": r.Format, "goodqa_project": r.GoodQAProject, "import_id": r.ImportID,
		"ledger_project": r.LedgerProject, "export_digest": r.ExportDigest, "base_digest": r.BaseDigest,
		"redacted": red, "frontier": fr, "tickets": tk, "imported_at_ms": r.ImportedMs}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	// ASCII only: every non-ASCII rune as \uXXXX (surrogate pairs above the BMP), as Python's ensure_ascii.
	var ascii bytes.Buffer
	for _, c := range string(out) {
		switch {
		case c < 0x80:
			ascii.WriteRune(c)
		case c < 0x10000:
			ascii.WriteString(`\u` + hex4(int(c)))
		default:
			c -= 0x10000
			ascii.WriteString(`\u` + hex4(0xd800+int(c>>10)) + `\u` + hex4(0xdc00+int(c&0x3ff)))
		}
	}
	return ascii.Bytes(), nil
}

func hex4(n int) string {
	const d = "0123456789abcdef"
	return string([]byte{d[n>>12&15], d[n>>8&15], d[n>>4&15], d[n&15]})
}

// SignedReceipt is the envelope.
type SignedReceipt struct {
	Format  string     `json:"format"`
	Receipt ReceiptDoc `json:"receipt"`
	Alg     string     `json:"alg"`
	KeyID   string     `json:"key_id"`
	Sig     string     `json:"sig"`
}

// KeyID is the first 16 hex of sha256 of the raw public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:16]
}

// Sign wraps the receipt in a signed envelope (used by tests and by a GoodQA reference implementation).
func (r *ReceiptDoc) Sign(priv ed25519.PrivateKey) (*SignedReceipt, error) {
	b, err := r.Canonical()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, append([]byte(signTag), b...))
	return &SignedReceipt{Format: SignedReceiptFormat, Receipt: *r, Alg: "ed25519",
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)), Sig: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

// Verify checks the envelope against the pinned key: algorithm, key id and signature.
func (e *SignedReceipt) Verify(pub ed25519.PublicKey) error {
	if e.Format != SignedReceiptFormat || e.Alg != "ed25519" {
		return errors.New("the receipt envelope is not goodqa-ledger-receipt-signed/v1 with ed25519")
	}
	if e.KeyID != KeyID(pub) {
		return errors.New("the receipt was signed with a different key than the pinned GoodQA key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("the receipt has no valid signature")
	}
	b, err := e.Receipt.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, append([]byte(signTag), b...), sig) {
		return errors.New("the receipt signature does not verify against the pinned GoodQA key")
	}
	return nil
}

// ParseKey reads a 32-byte ed25519 public key written as hex, base64 or PEM SPKI.
func ParseKey(raw []byte) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(string(raw))
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if pk, ok := k.(ed25519.PublicKey); err == nil && ok {
			return pk, nil
		}
		return nil, errors.New("the PEM is not an ed25519 SPKI public key")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, errors.New("the GoodQA key must be an ed25519 public key as 32 raw bytes in hex or base64, or PEM SPKI")
}
