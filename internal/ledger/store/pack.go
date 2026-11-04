package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

// RefPrefix is the namespace of own and promoted writer refs.
const RefPrefix = "refs/goodqa/v1/"

// RefName is refs/goodqa/v1/<proj>/log/<writer>.
func RefName(project, writer string) string { return RefPrefix + project + "/log/" + writer }

// ParseRefName splits a writer ref name; every component must be a well-formed id.
func ParseRefName(name string) (project, writer string, ok bool) {
	rest, found := strings.CutPrefix(name, RefPrefix)
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "log" || !op.ValidID(parts[0], op.PrefixProject) || !op.ValidID(parts[2], op.PrefixWriter) {
		return "", "", false
	}
	return parts[0], parts[2], true
}

const versionBlob = "1\n"

// ErrCASFailed means the ref moved between reading its tip and updating it.
var ErrCASFailed = errors.New("ledger ref moved concurrently")

// Tip returns the commit a ref points to, or "" when the ref does not exist.
func (g *Git) Tip(ref string) (string, error) {
	out, err := g.run(LocalTimeout, nil, nil, "for-each-ref", "--format=%(objectname)", ref)
	if err != nil {
		return "", err
	}
	ls := lines(out)
	if len(ls) == 0 {
		return "", nil
	}
	n, err := g.ObjectFormat()
	if err != nil {
		return "", err
	}
	return trimOID([]byte(ls[0]), n)
}

// Refs lists writer refs under RefPrefix as name -> tip. Names that are not well-formed are returned in
// bad (they are never read).
func (g *Git) Refs() (refs map[string]string, bad []string, err error) {
	out, err := g.run(LocalTimeout, nil, nil, "for-each-ref", "--format=%(refname) %(objectname)", RefPrefix)
	if err != nil {
		return nil, nil, err
	}
	refs = map[string]string{}
	for _, l := range lines(out) {
		name, oid, _ := strings.Cut(l, " ")
		if _, _, ok := ParseRefName(name); !ok {
			bad = append(bad, name)
			continue
		}
		refs[name] = oid
	}
	return refs, bad, nil
}

// LeaseHash is the commit-message form of a writer lease: sha256(lease)[:16].
func LeaseHash(lease string) string {
	s := sha256.Sum256([]byte(lease))
	return hex.EncodeToString(s[:])[:16]
}

// WritePack stores ops as one commit on top of parent ("" for the first pack) and returns its id.
// The tree is exactly version-1, hlc-<wall>-<ctr> (the last op's clock) and ops.jsonl. Pack commits are
// never signed: signing would run gpg.program (and possibly a pinentry prompt) inside the writer lock.
func (g *Git) WritePack(parent string, ops []*op.Op, lease string) (string, error) {
	if len(ops) == 0 {
		return "", errors.New("empty pack")
	}
	var body bytes.Buffer
	for _, o := range ops {
		body.Write(o.Raw)
		body.WriteByte('\n')
	}
	if body.Len() > op.MaxPackBytes {
		return "", fmt.Errorf("pack exceeds %d bytes", op.MaxPackBytes)
	}
	n, err := g.ObjectFormat()
	if err != nil {
		return "", err
	}
	hash := func(content []byte) (string, error) {
		out, err := g.run(LocalTimeout, content, nil, "hash-object", "-w", "--stdin")
		if err != nil {
			return "", err
		}
		return trimOID(out, n)
	}
	vb, err := hash([]byte(versionBlob))
	if err != nil {
		return "", err
	}
	hb, err := hash(nil)
	if err != nil {
		return "", err
	}
	ob, err := hash(body.Bytes())
	if err != nil {
		return "", err
	}
	last := ops[len(ops)-1].HLC
	tree := fmt.Sprintf("100644 blob %s\t%s\n100644 blob %s\tops.jsonl\n100644 blob %s\tversion-1\n", hb, last.Name(), ob, vb)
	out, err := g.run(LocalTimeout, []byte(tree), nil, "mktree")
	if err != nil {
		return "", err
	}
	treeID, err := trimOID(out, n)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("ledger: %d ops %s..%s lease:%s\n", len(ops), ops[0].HLC.Name(), last.Name(), LeaseHash(lease))
	date := fmt.Sprintf("@%d +0000", last.WallMs/1000)
	id := []string{"GIT_AUTHOR_NAME=" + CommitName, "GIT_AUTHOR_EMAIL=" + CommitEmail, "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=" + CommitName, "GIT_COMMITTER_EMAIL=" + CommitEmail, "GIT_COMMITTER_DATE=" + date}
	args := []string{"commit-tree", "--no-gpg-sign", treeID, "-F", "-"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	out, err = g.run(LocalTimeout, []byte(msg), id, args...)
	if err != nil {
		return "", err
	}
	return trimOID(out, n)
}

// CAS moves ref from old ("" = must not exist) to new. Any other current value fails with ErrCASFailed.
func (g *Git) CAS(ref, newID, old string) error {
	n, err := g.ObjectFormat()
	if err != nil {
		return err
	}
	if old == "" {
		old = zeroOID(n)
	}
	if _, err := g.run(LocalTimeout, nil, nil, "update-ref", "--no-deref", ref, newID, old); err != nil {
		var ge *GitError
		if errors.As(err, &ge) {
			return ErrCASFailed
		}
		return err
	}
	return nil
}

// Pack is one validated pack commit.
type Pack struct {
	Commit string
	Ops    []*op.Op
	HLC    op.HLC
	Lease  string // lease hash from the commit message
}

// object is one cat-file --batch result.
type object struct {
	typ  string
	body []byte
}

// batch reads objects by name with one cat-file process, refusing any object larger than its limit and
// any request whose objects together exceed total (sizes are checked with --batch-check before any
// content is read).
func (g *Git) batch(names []string, limit func(i int, typ string) int64, total int64) ([]object, error) {
	if len(names) == 0 {
		return nil, nil
	}
	in := []byte(strings.Join(names, "\n") + "\n")
	out, err := g.run(LocalTimeout, in, nil, "cat-file", "--batch-check=%(objecttype) %(objectsize)")
	if err != nil {
		return nil, err
	}
	checks := lines(out)
	if len(checks) != len(names) {
		return nil, errors.New("cat-file returned an unexpected number of objects")
	}
	for i, c := range checks {
		typ, size, ok := strings.Cut(c, " ")
		sz, err := strconv.ParseInt(size, 10, 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("object %d missing", i)
		}
		if sz > limit(i, typ) {
			return nil, fmt.Errorf("object %d (%s) exceeds its size limit", i, typ)
		}
		if total -= sz; total < 0 {
			return nil, errors.New("writer ref exceeds its read budget")
		}
	}
	out, err = g.run(LocalTimeout, in, nil, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(bytes.NewReader(out))
	objs := make([]object, 0, len(names))
	for range names {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, errors.New("cat-file output truncated")
		}
		f := strings.Fields(hdr)
		if len(f) != 3 {
			return nil, errors.New("cat-file object missing")
		}
		sz, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || sz < 0 {
			return nil, errors.New("cat-file bad size")
		}
		body := make([]byte, sz)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, errors.New("cat-file output truncated")
		}
		if b, _ := r.ReadByte(); b != '\n' {
			return nil, errors.New("cat-file framing")
		}
		objs = append(objs, object{f[1], body})
	}
	return objs, nil
}

type treeEntry struct{ mode, name, oid string }

func parseTree(body []byte, n int) ([]treeEntry, error) {
	var out []treeEntry
	raw := n / 2
	for len(body) > 0 {
		sp := bytes.IndexByte(body, ' ')
		nul := bytes.IndexByte(body, 0)
		if sp < 0 || nul < sp || len(body) < nul+1+raw {
			return nil, errors.New("malformed tree")
		}
		out = append(out, treeEntry{string(body[:sp]), string(body[sp+1 : nul]), hex.EncodeToString(body[nul+1 : nul+1+raw])})
		body = body[nul+1+raw:]
	}
	return out, nil
}

// MaxChain bounds the commits read from one folded writer ref; UnverifiedMaxChain bounds those read from
// a ref anyone who can write the repository could have planted, so its commit walk stays cheap.
const (
	MaxChain           = 100000
	UnverifiedMaxChain = 4096
)

// Read budgets: the bytes of commits, trees and blobs one writer ref may make the ledger read. A folded
// (self) ref gets room for years of use; a ref from an unverified or blocked writer, which anyone who can
// write the repository can plant, gets a small one so it cannot exhaust memory or time.
const (
	FoldedBudget     = int64(1) << 30
	UnverifiedBudget = int64(16) << 20
	// UnverifiedViewBudget is shared by all unverified refs in one view, so many planted refs together
	// cannot make one read hold more than this.
	UnverifiedViewBudget = int64(64) << 20
)

// ReadRef reads and validates every pack on a writer ref with the folded budget.
func (g *Git) ReadRef(project, writer, tip string) ([]Pack, error) {
	budget := FoldedBudget
	return g.ReadRefBudget(project, writer, tip, &budget, MaxChain)
}

// ReadRefBudget reads and validates every pack on a writer ref, oldest first, reading at most *budget
// bytes from a chain of at most maxChain commits. The bytes read are taken off *budget as they are read,
// also when the ref is then rejected (an over-budget batch is refused from its sizes, before reading). Any
// defect rejects the whole ref (the returned error says why); nothing from a rejected ref is used.
func (g *Git) ReadRefBudget(project, writer, tip string, budgetp *int64, maxChain int) ([]Pack, error) {
	budget := *budgetp
	n, err := g.ObjectFormat()
	if err != nil {
		return nil, err
	}
	out, err := g.run(LocalTimeout, nil, nil, "rev-list", "--parents", "--reverse", fmt.Sprintf("--max-count=%d", maxChain+1), tip)
	if err != nil {
		return nil, err
	}
	var commits []string
	prev := ""
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) == 0 || len(f) > 2 {
			return nil, errors.New("merge commit on a writer ref")
		}
		if (prev == "" && len(f) != 1) || (prev != "" && (len(f) != 2 || f[1] != prev)) {
			return nil, errors.New("writer ref is not a linear chain")
		}
		commits = append(commits, f[0])
		prev = f[0]
	}
	if len(commits) == 0 || len(commits) > maxChain {
		return nil, errors.New("writer ref chain empty or too long")
	}
	names := make([]string, 0, 2*len(commits))
	for _, c := range commits {
		names = append(names, c, c+"^{tree}")
	}
	objs, err := g.batch(names, func(i int, typ string) int64 { return 64 * 1024 }, budget)
	if err != nil {
		return nil, err
	}
	packs := make([]Pack, len(commits))
	var blobNames []string
	type want struct{ ops, hlc, ver string }
	wants := make([]want, len(commits))
	seenOps := map[string]bool{}
	for _, o := range objs {
		budget -= int64(len(o.body))
	}
	*budgetp = budget
	for i, c := range commits {
		co, tr := objs[2*i], objs[2*i+1]
		if co.typ != "commit" || tr.typ != "tree" {
			return nil, errors.New("unexpected object type")
		}
		// rev-list's parents can come from a commit-graph or info/grafts file that travels with a copied
		// .git; the commit object itself must name the same single parent.
		parent := ""
		if i > 0 {
			parent = commits[i-1]
		}
		if commitParents(co.body) != parent {
			return nil, errors.New("commit parents differ from the walked chain")
		}
		packs[i].Commit = c
		packs[i].Lease = leaseFromMessage(co.body)
		entries, err := parseTree(tr.body, n)
		if err != nil {
			return nil, err
		}
		if len(entries) != 3 {
			return nil, errors.New("pack tree must have exactly version-1, hlc-* and ops.jsonl")
		}
		var w want
		for _, e := range entries {
			if e.mode != "100644" {
				return nil, errors.New("pack tree entry is not a regular blob")
			}
			switch {
			case e.name == "version-1":
				w.ver = e.oid
			case e.name == "ops.jsonl":
				w.ops = e.oid
			case strings.HasPrefix(e.name, "hlc-"):
				h, err := op.ParseHLCName(e.name)
				if err != nil {
					return nil, err
				}
				packs[i].HLC = h
				w.hlc = e.oid
			default:
				return nil, fmt.Errorf("unexpected pack tree entry")
			}
		}
		if w.ver == "" || w.ops == "" || w.hlc == "" {
			return nil, errors.New("pack tree incomplete")
		}
		wants[i] = w
		if seenOps[w.ops] {
			// Every pack carries new ops with strictly larger clocks, so a reused ops blob is never valid:
			// refuse it before reading (one large blob shared by many commits would be read many times).
			return nil, errors.New("ops blob reused by two packs")
		}
		seenOps[w.ops] = true
		blobNames = append(blobNames, w.ver, w.ops)
	}
	blobs, err := g.batch(blobNames, func(i int, typ string) int64 {
		if i%2 == 0 {
			return 16
		}
		return op.MaxPackBytes
	}, budget)
	if err != nil {
		return nil, err
	}
	for _, o := range blobs {
		budget -= int64(len(o.body))
	}
	*budgetp = budget
	var last op.HLC
	first := true
	for i := range packs {
		ver, body := blobs[2*i], blobs[2*i+1]
		if ver.typ != "blob" || body.typ != "blob" || string(ver.body) != versionBlob {
			return nil, errors.New("pack version blob is not version 1")
		}
		if len(body.body) == 0 || body.body[len(body.body)-1] != '\n' {
			return nil, errors.New("ops.jsonl must end with a newline")
		}
		for _, line := range bytes.Split(body.body[:len(body.body)-1], []byte("\n")) {
			o, err := op.Parse(line)
			if err != nil {
				return nil, err
			}
			if o.Project != project || o.Writer != writer {
				return nil, errors.New("op project or writer differs from its ref")
			}
			if !first && !last.Less(o.HLC) {
				return nil, errors.New("op clocks are not strictly increasing on the ref")
			}
			first, last = false, o.HLC
			packs[i].Ops = append(packs[i].Ops, o)
		}
		if packs[i].HLC != last {
			return nil, errors.New("hlc-* entry differs from the last op clock")
		}
	}
	return packs, nil
}

// TipHLC reads only the hlc-* entry of a pack commit's tree (the authoritative last clock).
func (g *Git) TipHLC(tip string) (op.HLC, error) {
	out, err := g.run(LocalTimeout, nil, nil, "ls-tree", "--name-only", tip)
	if err != nil {
		return op.HLC{}, err
	}
	var h op.HLC
	found := 0
	for _, name := range lines(out) {
		if strings.HasPrefix(name, "hlc-") {
			if h, err = op.ParseHLCName(name); err != nil {
				return op.HLC{}, err
			}
			found++
		}
	}
	if found != 1 {
		return op.HLC{}, errors.New("tip has no single hlc-* entry")
	}
	return h, nil
}

// commitParents returns the commit header's parent ids joined by spaces ("" for a root commit).
func commitParents(commit []byte) string {
	hdr, _, _ := bytes.Cut(commit, []byte("\n\n"))
	var ps []string
	for _, l := range strings.Split(string(hdr), "\n") {
		if p, ok := strings.CutPrefix(l, "parent "); ok {
			ps = append(ps, p)
		}
	}
	return strings.Join(ps, " ")
}

func leaseFromMessage(commit []byte) string {
	_, msg, _ := bytes.Cut(commit, []byte("\n\n"))
	i := bytes.LastIndex(msg, []byte("lease:"))
	if i < 0 || len(msg) < i+6+16 {
		return ""
	}
	return string(msg[i+6 : i+6+16])
}
