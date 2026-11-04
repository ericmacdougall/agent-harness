package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

const base = int64(1793664000000)

func bare(t *testing.T) *Git {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("store tests drive POSIX git fixtures")
	}
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "r.git")
	if err := InitBare(dir, "ledger"); err != nil {
		t.Fatal(err)
	}
	return &Git{GitDir: dir}
}

func mkOp(t *testing.T, project, writer string, h op.HLC, kind string) *op.Op {
	t.Helper()
	id, err := op.NewID(op.PrefixOp, h.WallMs)
	if err != nil {
		t.Fatal(err)
	}
	o := &op.Op{V: 1, ID: id, Project: project, Writer: writer, HLC: h, Actor: op.Actor{Kind: "agent", Label: "t"}, Kind: kind}
	switch kind {
	case op.KindProjectCreate:
		o.Payload = op.ProjectCreate("demo", "demo", op.DefaultStatuses)
	default:
		o.Ticket = op.PrefixTicket + id[len(op.PrefixOp):]
		o.Payload = op.TicketCreate("title", "", "task", "medium", nil, "todo", "unstarted")
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := op.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ids(t *testing.T) (string, string) {
	t.Helper()
	project, _ := op.NewID(op.PrefixProject, base)
	writer, _ := op.NewID(op.PrefixWriter, base)
	return project, writer
}

// CAS is a compare-and-swap: a stale old value, or a create over an existing ref, fails with ErrCASFailed.
func TestCASRefusesStaleOldValue(t *testing.T) {
	g := bare(t)
	project, writer := ids(t)
	ref := RefName(project, writer)
	c1, err := g.WritePack("", []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base}, op.KindProjectCreate)}, "lease")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(ref, c1, ""); err != nil {
		t.Fatal(err)
	}
	c2, err := g.WritePack(c1, []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base + 1}, op.KindTicketCreate)}, "lease")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(ref, c2, ""); !errors.Is(err, ErrCASFailed) {
		t.Fatalf("create over an existing ref: %v", err)
	}
	c3, _ := g.WritePack(c1, []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base + 2}, op.KindTicketCreate)}, "lease")
	if err := g.CAS(ref, c2, c1); err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(ref, c3, c1); !errors.Is(err, ErrCASFailed) {
		t.Fatalf("stale old value accepted: %v", err)
	}
	if tip, _ := g.Tip(ref); tip != c2 {
		t.Fatalf("tip moved to %s", tip)
	}
}

// A pack commit has exactly version-1, one hlc entry equal to its last op, and ops.jsonl; the fixed
// identity; and no signature even when the repository asks for one.
func TestPackShapeAndValidation(t *testing.T) {
	g := bare(t)
	project, writer := ids(t)
	ref := RefName(project, writer)
	ops := []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base}, op.KindProjectCreate),
		mkOp(t, project, writer, op.HLC{WallMs: base, Ctr: 1}, op.KindTicketCreate)}
	c, err := g.WritePack("", ops, "lease")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(ref, c, ""); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "--git-dir="+g.GitDir, "ls-tree", "--name-only", c).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out)); strings.Join(got, ",") != "hlc-1793664000000-1,ops.jsonl,version-1" {
		t.Fatalf("tree %v", got)
	}
	who, _ := exec.Command("git", "--git-dir="+g.GitDir, "log", "-1", "--format=%an <%ae> %at", c).Output()
	if strings.TrimSpace(string(who)) != "goodqa-ledger <ledger@goodqa.invalid> 1793664000" {
		t.Fatalf("identity %q", who)
	}
	packs, err := g.ReadRef(project, writer, c)
	if err != nil || len(packs) != 1 || len(packs[0].Ops) != 2 {
		t.Fatalf("ReadRef: %v %v", packs, err)
	}
	if h, err := g.TipHLC(c); err != nil || h != (op.HLC{WallMs: base, Ctr: 1}) {
		t.Fatalf("TipHLC %v %v", h, err)
	}
	// A clock that does not increase across packs makes the whole ref invalid.
	bad, _ := g.WritePack(c, []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base}, op.KindTicketCreate)}, "lease")
	if _, err := g.ReadRef(project, writer, bad); err == nil {
		t.Fatal("non-monotonic clock accepted")
	}
	// Ops for another writer on this ref are refused.
	other2, _ := op.NewID(op.PrefixWriter, base+5)
	alien, _ := g.WritePack(c, []*op.Op{mkOp(t, project, other2, op.HLC{WallMs: base + 9}, op.KindTicketCreate)}, "lease")
	if _, err := g.ReadRef(project, writer, alien); err == nil {
		t.Fatal("foreign writer op accepted on this ref")
	}
}

// A tree with an extra entry is not a pack.
func TestExtraTreeEntryRejected(t *testing.T) {
	g := bare(t)
	project, writer := ids(t)
	c, err := g.WritePack("", []*op.Op{mkOp(t, project, writer, op.HLC{WallMs: base}, op.KindProjectCreate)}, "lease")
	if err != nil {
		t.Fatal(err)
	}
	run := func(stdin string, args ...string) string {
		cmd := exec.Command("git", append([]string{"--git-dir=" + g.GitDir}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=x", "GIT_AUTHOR_EMAIL=x@x", "GIT_COMMITTER_NAME=x", "GIT_COMMITTER_EMAIL=x@x")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	tree := run("", "ls-tree", c)
	blob := run("x", "hash-object", "-w", "--stdin")
	tree2 := run(tree+"\n100644 blob "+blob+"\textra\n", "mktree")
	c2 := run("ledger: 1 ops\n", "commit-tree", tree2)
	if _, err := g.ReadRef(project, writer, c2); err == nil {
		t.Fatal("extra tree entry accepted")
	}
}
