package cli

// Phase 0b commands: sync-state, bind, export --format goodqa-import, trust-writer, block-writer.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/term"
)

const (
	maxReceiptBytes   = 1 << 20
	maxReceiptTickets = 100000
)

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	importIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	handleRe   = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	digestRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func refusedf(format string, a ...any) error {
	return &codedErr{kind: errRefusedKind, msg: fmt.Sprintf(format, a...)}
}

func cmdSyncState(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	if len(p.pos) > 0 {
		return usagef("sync-state takes no positional arguments")
	}
	tracked, known := false, false
	if p.get("slug") == "" {
		tracked, known = ledger.Tracked(env.Cwd)
	}
	report := ledger.SyncReport{State: ledger.StateNone}
	slug, project, presence := "", "", "absent"
	l, err := open(p, env)
	switch {
	case err == nil:
		defer l.Close()
		slug, project, presence = l.Slug, l.Project, "present"
		in, serr := l.Snapshot()
		if serr != nil || fold.Fold(in).Slug != l.Slug {
			// This HOME cannot use the ledger (a copied .git, a damaged ref): never report it synced.
			presence = "unusable"
			report = ledger.SyncReport{State: ledger.StateNone}
		} else {
			report = l.SyncState(in, tracked)
		}
	case errors.Is(err, ledger.ErrNoLedger):
		if tracked {
			report.State = ledger.StateTracked
		}
	default:
		presence = "unusable"
	}
	if report.State == ledger.StateNone && tracked {
		report.State = ledger.StateTracked
	}
	doc := op.Obj{{K: "state", V: report.State}, {K: "ledger", V: presence}, {K: "slug", V: slug}, {K: "project", V: project},
		{K: "unsynced_ops", V: report.Unsynced}, {K: "writers", V: report.Writers}, {K: "goodqa_project", V: report.GoodQAProject},
		{K: "tracked", V: tracked}, {K: "tracked_known", V: known}, {K: "authenticated", V: report.Authenticated}}
	emit(env, p.has("json"), doc, fmt.Sprintf("%s\n", report.State))
	return nil
}

// ---------------------------------------------------------------------------------------- receipt

func readReceipt(path string, env Env) (*ledger.ReceiptDoc, *ledger.SignedReceipt, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(env.Cwd, path)
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, nil, usagef("--receipt must be a regular file")
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, usagef("cannot read --receipt")
	}
	defer fh.Close()
	if fi, err := fh.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, nil, usagef("--receipt must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(fh, maxReceiptBytes+1))
	if err != nil || len(raw) > maxReceiptBytes {
		return nil, nil, refusedf("receipt is unreadable or larger than %d bytes", maxReceiptBytes)
	}
	var probe struct {
		Format string `json:"format"`
	}
	_ = json.Unmarshal(raw, &probe)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r ledger.ReceiptDoc
	var signed *ledger.SignedReceipt
	if probe.Format == ledger.SignedReceiptFormat {
		signed = &ledger.SignedReceipt{}
		if err := dec.Decode(signed); err != nil || dec.More() {
			return nil, nil, refusedf("receipt envelope is not goodqa-ledger-receipt-signed/v1 (unknown or missing fields)")
		}
		r = signed.Receipt
	} else if err := dec.Decode(&r); err != nil || dec.More() {
		return nil, nil, refusedf("receipt is not the goodqa-ledger-receipt/v1 document (unknown or missing fields)")
	}
	if len(r.Tickets) > maxReceiptTickets {
		return nil, nil, refusedf("receipt lists more than %d tickets", maxReceiptTickets)
	}
	switch {
	case r.Redacted == nil:
		return nil, nil, refusedf("receipt must say whether the export was redacted (redacted: true or false)")
	case r.Format != ledger.ReceiptFormat:
		return nil, nil, refusedf("receipt format is not %s", ledger.ReceiptFormat)
	case !uuidRe.MatchString(r.GoodQAProject):
		return nil, nil, refusedf("receipt goodqa_project is not a UUID")
	case !importIDRe.MatchString(r.ImportID):
		return nil, nil, refusedf("receipt import_id is empty or malformed")
	case !op.ValidID(r.LedgerProject, op.PrefixProject):
		return nil, nil, refusedf("receipt ledger_project is malformed")
	case !digestRe.MatchString(r.ExportDigest) || (r.BaseDigest != "" && !digestRe.MatchString(r.BaseDigest)):
		return nil, nil, refusedf("receipt digests must be 64 hex characters")
	case len(r.Frontier) == 0 || len(r.Frontier) > 4096:
		return nil, nil, refusedf("receipt frontier is empty or too large")
	}
	for _, t := range r.Tickets {
		if !handleRe.MatchString(t.Handle) || t.Number < 1 {
			return nil, nil, refusedf("receipt ticket entry is malformed")
		}
	}
	seenW := map[string]bool{}
	for _, f := range r.Frontier {
		if seenW[f.Writer] {
			return nil, nil, refusedf("receipt frontier lists a writer twice")
		}
		seenW[f.Writer] = true
		if !op.ValidID(f.Writer, op.PrefixWriter) || !op.ValidID(f.LastOp, op.PrefixOp) || f.Ops < 1 || f.Ops > 1<<30 {
			return nil, nil, refusedf("receipt frontier entry is malformed")
		}
	}
	return &r, signed, nil
}

func cmdBind(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"project": true, "receipt": true, "goodqa-key": true}))
	if err != nil {
		return err
	}
	if !p.has("project") || !p.has("receipt") || len(p.pos) > 0 {
		return usagef("usage: bind --project UUID --receipt FILE")
	}
	if !uuidRe.MatchString(p.get("project")) {
		return usagef("--project must be a GoodQA project UUID")
	}
	rc, signed, err := readReceipt(p.get("receipt"), env)
	if err != nil {
		return err
	}
	if rc.GoodQAProject != p.get("project") {
		return refusedf("the receipt is for a different GoodQA project than --project")
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	if rc.LedgerProject != l.Project {
		return refusedf("the receipt is for a different ledger")
	}
	var bound *ledger.Binding
	err = l.Locked(func() error {
		in, err := l.Snapshot()
		if err != nil {
			return err
		}
		if fold.Fold(in).Slug != l.Slug {
			return refusedf("this ledger cannot be opened by this HOME")
		}
		cur := l.ReadBinding()
		if cur != nil && cur.Damaged {
			return refusedf("this HOME's binding state is damaged; run unbind, then bind again with a signed receipt and --goodqa-key to restore the pinned key")
		}
		var from []ledger.Frontier
		base := ""
		if cur != nil {
			from, base = cur.Frontier, cur.ExportDigest
		}
		if rc.BaseDigest != base {
			return refusedf("the receipt's base_digest is not this ledger's current binding")
		}
		// A pinned GoodQA key makes the receipt authenticated: once pinned, an unsigned or badly signed receipt
		// is refused. Without one the receipt stays advisory (its digest is public).
		var key ed25519.PublicKey
		if kf := p.get("goodqa-key"); kf != "" {
			raw, kerr := readSmallFile(kf, env)
			if kerr != nil {
				return kerr
			}
			if key, kerr = ledger.ParseKey(raw); kerr != nil {
				return usagef("%v", kerr)
			}
		}
		pinned := ""
		if cur != nil {
			pinned = cur.GoodQAKey
		}
		if key != nil && pinned != "" && hex.EncodeToString(key) != pinned {
			return refusedf("a different GoodQA key is already pinned for this ledger")
		}
		if key == nil && pinned != "" {
			var perr error
			if key, perr = ledger.ParseKey([]byte(pinned)); perr != nil {
				return refusedf("the pinned GoodQA key in this HOME's state is unreadable; run unbind and bind again")
			}
		}
		if key != nil {
			if signed == nil {
				return refusedf("a GoodQA key is pinned for this ledger, so the receipt must be a signed envelope")
			}
			if verr := signed.Verify(key); verr != nil {
				return refusedf("%v", verr)
			}
		}
		to := make([]ledger.Frontier, len(rc.Frontier))
		for i, f := range rc.Frontier {
			to[i] = ledger.Frontier{Writer: f.Writer, Ops: f.Ops, WallMs: f.WallMs, Ctr: f.Ctr, LastOp: f.LastOp}
		}
		// Rebuild in the receipt's own mode: a redacted receipt is never matched against a plain document.
		var firstErr error
		doc, berr := ledger.BuildImport(in, from, to, base, *rc.Redacted)
		if berr != nil {
			firstErr = berr
		}
		if berr != nil || doc.Digest != rc.ExportDigest {
			if firstErr != nil {
				var se *ledger.SecretError
				if errors.As(firstErr, &se) {
					return refusedf("this ledger holds secret-shaped text; the receipt must be for a redacted export")
				}
				return refusedf("the receipt's frontier is not a prefix of this ledger: %s", term.Line(firstErr.Error()))
			}
			return refusedf("the receipt's export_digest does not match this ledger at its frontier")
		}
		now, err := ledger.Now()
		if err != nil {
			return err
		}
		bound = &ledger.Binding{GoodQAProject: rc.GoodQAProject, ImportID: rc.ImportID, ExportDigest: rc.ExportDigest, BoundMs: now, Frontier: to}
		if key != nil {
			bound.GoodQAKey = hex.EncodeToString(key)
		}
		return l.WriteBinding(bound)
	})
	if err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "bound", V: true}, {K: "goodqa_project", V: bound.GoodQAProject},
		{K: "import_id", V: bound.ImportID}, {K: "export_digest", V: bound.ExportDigest}},
		fmt.Sprintf("bound ledger %s to GoodQA project %s\n", l.Slug, bound.GoodQAProject))
	return nil
}

// exportImport writes the goodqa-import document (full, or only what follows the binding).
func exportImport(p parsed, env Env, l *ledger.Ledger) (string, error) {
	in, err := l.Snapshot()
	if err != nil {
		return "", err
	}
	if fold.Fold(in).Slug != l.Slug {
		return "", refusedf("this ledger cannot be opened by this HOME")
	}
	to := ledger.FoldedFrontier(in)
	var from []ledger.Frontier
	base := ""
	if p.has("since-bound") {
		b := l.ReadBinding()
		if b == nil {
			return "", usagef("--since-bound needs a bound ledger (see `bind`)")
		}
		if b.Damaged {
			return "", refusedf("this HOME's binding state is damaged; run unbind, then bind again with a signed receipt and --goodqa-key to restore the pinned key")
		}
		if rel, _ := ledger.Compare(in, b.Frontier); rel == ledger.RelDiverged {
			return "", refusedf("the binding no longer matches this ledger; export without --since-bound")
		}
		from, base = b.Frontier, b.ExportDigest
	}
	doc, err := ledger.BuildImport(in, from, to, base, p.has("redact-secrets"))
	if err != nil {
		var se *ledger.SecretError
		if errors.As(err, &se) {
			return "", &codedErr{kind: ledger.ErrSecret, msg: term.Line(err.Error())}
		}
		return "", err
	}
	return string(doc.Body), nil
}

// ---------------------------------------------------------------------------------------- trust

func writerArg(p parsed, cmd string) (string, error) {
	if len(p.pos) != 1 || !op.ValidID(p.pos[0], op.PrefixWriter) {
		return "", usagef("usage: %s w_<writer id>", cmd)
	}
	return p.pos[0], nil
}

func cmdTrustWriter(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"reviewed": true}))
	if err != nil {
		return err
	}
	w, err := writerArg(p, "trust-writer w_... --reviewed DIGEST")
	if err != nil {
		return err
	}
	if !digestRe.MatchString(p.get("reviewed")) {
		return usagef("--reviewed must be the 64-hex digest `writers --show %s` prints", w)
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	if !l.InRepo {
		return refusedf("a repo-less ledger has only this machine's writers")
	}
	err = l.Locked(func() error {
		ops, digest, class, err := l.WriterReview(w)
		if err != nil {
			return err
		}
		if class == fold.ClassSelf {
			return refusedf("%s is this machine's own writer", w)
		}
		if digest != p.get("reviewed") {
			return refusedf("--reviewed does not match the writer's current ops (review `writers --show %s` again)", w)
		}
		t := l.ReadTrust()
		delete(t.Blocked, w)
		t.Trusted[w] = ledger.TrustEntry{Ops: len(ops), Digest: digest}
		return l.WriteTrust(t)
	})
	if err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "writer", V: w}, {K: "trusted", V: true}}, fmt.Sprintf("trusted %s\n", w))
	return nil
}

func cmdBlockWriter(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	w, err := writerArg(p, "block-writer w_...")
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	if !l.InRepo {
		return refusedf("a repo-less ledger has only this machine's writers")
	}
	err = l.Locked(func() error {
		_, _, class, err := l.WriterReview(w)
		if err != nil {
			return err
		}
		if class == fold.ClassSelf {
			return refusedf("%s is this machine's own writer; it cannot be blocked", w)
		}
		t := l.ReadTrust()
		delete(t.Trusted, w)
		t.Blocked[w] = true
		return l.WriteTrust(t)
	})
	if err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "writer", V: w}, {K: "blocked", V: true}}, fmt.Sprintf("blocked %s\n", w))
	return nil
}

// wholeText renders an op for review without losing a byte to the 2,000-character line cap: it is cut into
// chunks, each sanitized on its own, and rejoined. The review digest covers exactly this text.
func wholeText(raw string) string {
	rs := []rune(raw)
	var b strings.Builder
	for len(rs) > 0 {
		n := min(1500, len(rs))
		b.WriteString(s(string(rs[:n])))
		rs = rs[n:]
	}
	return b.String()
}

// writersWithoutRoot lists writers when no folded writer holds the project root yet (a freshly adopted
// ledger): the view cannot be built, but the writers can be reviewed and trusted.
func writersWithoutRoot(p parsed, l *ledger.Ledger, env Env, viewErr error) error {
	if p.has("show") {
		w := p.get("show")
		ops, digest, class, err := l.WriterReview(w)
		if err != nil {
			return err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "writer %s class %s, %d ops (untrusted data below; not folded unless self or trusted)\n", w, class, len(ops))
		texts := []string{}
		for _, o := range ops {
			t := string(o.Raw) // the whole op: the review digest covers exactly what is shown
			texts = append(texts, wholeText(t))
			fmt.Fprintf(&b, "  op %s\n", wholeText(t))
		}
		fmt.Fprintf(&b, "review digest %s (covers all %d ops; trust-writer %s --reviewed DIGEST)\n", digest, len(ops), w)
		emit(env, p.has("json"), op.Obj{{K: "writer", V: w}, {K: "class", V: class}, {K: "ops", V: len(ops)},
			{K: "review_digest", V: digest}, {K: "ops_text", V: texts}}, b.String())
		return nil
	}
	in, err := l.Snapshot()
	if err != nil {
		return err
	}
	rows := []op.Obj{}
	var b strings.Builder
	fmt.Fprintf(&b, "no trusted or own writer holds the project root yet (%s)\n", term.Line(viewErr.Error()))
	for _, r := range in.Refs {
		rows = append(rows, op.Obj{{K: "id", V: r.Writer}, {K: "class", V: in.Class(r.Writer)}, {K: "ops", V: len(r.Ops)}, {K: "rejected", V: term.Line(r.Rejected)}})
		fmt.Fprintf(&b, "%s %-10s %4d ops %s\n", r.Writer, in.Class(r.Writer), len(r.Ops), term.Line(r.Rejected))
	}
	emit(env, p.has("json"), op.Obj{{K: "project", V: l.Project}, {K: "writers", V: rows}}, b.String())
	return nil
}

// readSmallFile reads a regular file of at most 4 KiB (a key file).
func readSmallFile(path string, env Env) ([]byte, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(env.Cwd, path)
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4096 {
		return nil, usagef("--goodqa-key must be a regular file of at most 4 KiB")
	}
	return os.ReadFile(path)
}

// cmdUnbind forgets the GoodQA binding (and a pinned key) so the ledger can be imported afresh. The caller
// must type the ledger's slug: it is a deliberate act, not something to run by accident.
func cmdUnbind(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"confirm": true}))
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	if p.get("confirm") != l.Slug {
		return refusedf("unbind forgets the GoodQA binding and any pinned key; confirm with --confirm %s", l.Slug)
	}
	if err := l.Unbind(); err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "unbound", V: true}}, fmt.Sprintf("ledger %s is no longer bound to GoodQA\n", l.Slug))
	return nil
}
