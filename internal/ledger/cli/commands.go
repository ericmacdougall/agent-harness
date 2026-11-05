package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/term"
)

// Usage is printed for usage errors.
const Usage = `usage: harness tickets <command> [options]
  init [--slug S] [--name N] [--no-repo] [--from-mirror]
  new --title T [--body B | --body-file F] [--type task|bug|feature|chore] [--priority none|low|medium|high|urgent] [--label L]... [--status S]
  list [--status S] [--label L]
  show <handle> [--history] [--as-of MS] [--min-version V]
  move <handle> <status>
  comment <handle> (--body B | --body-file F)
  edit <handle> [--title T] [--body B | --body-file F] [--priority P] [--type T]
  label <handle> [--add L]... [--remove L]...
  status [--agent-snippet]
  writers [--show w_...]
  rebuild
  export [--format md|json|goodqa-import] [--out PATH] [--since-bound] [--redact-secrets]
  sync-state
  bind --project UUID --receipt FILE
  trust-writer w_... --reviewed DIGEST
  block-writer w_...
  travel enable --remote NAME [--yes-share TOKEN] | status | push | fetch [--adopt --remote NAME --yes-share TOKEN]
common: --json (reads and writes), --slug S (select a repo-less ledger outside a repository),
        --redact-secrets (mask secret-shaped text instead of refusing), --actor-label L
exit codes: 0 ok, 2 usage/validation, 3 refused/not found/ambiguous, 6 ledger busy`

// Env is what a command needs from its process (injectable for the MCP server and tests).
type Env struct {
	Cwd    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
}

var common = spec{"json": false, "slug": true, "redact-secrets": false, "actor-label": true}

func merge(a spec) spec {
	out := spec{}
	for k, v := range common {
		out[k] = v
	}
	for k, v := range a {
		out[k] = v
	}
	return out
}

// DefaultActor derives claimed actor metadata from the environment (no names or hosts).
func DefaultActor(getenv func(string) string, label string) (op.Actor, error) {
	a := op.Actor{Kind: "human", Label: "cli"}
	switch {
	case getenv("CLAUDECODE") != "" || getenv("CLAUDE_CODE_ENTRYPOINT") != "":
		a = op.Actor{Kind: "agent", Label: "claude-code"}
	case getenv("CODEX_THREAD_ID") != "" || getenv("CODEX_SANDBOX") != "" || getenv("CODEX_HOME") != "":
		a = op.Actor{Kind: "agent", Label: "codex"}
	case getenv("CURSOR_TRACE_ID") != "" || getenv("CURSOR_AGENT") != "":
		a = op.Actor{Kind: "agent", Label: "cursor"}
	case getenv("HARNESS_AGENT") != "":
		a = op.Actor{Kind: "agent", Label: "agent"}
	}
	if label != "" {
		if !op.ValidActorLabel(label) {
			return a, usagef("--actor-label must be 1-64 chars of [A-Za-z0-9 ._/@:+-]")
		}
		a.Label = label
	}
	return a, nil
}

// Main runs `harness tickets <args>` and returns the exit code.
func Main(args []string, env Env) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(env.Stdout, Usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	asJSON := false
	for _, a := range rest {
		if a == "--json" {
			asJSON = true
		}
	}
	err := ledger.CheckTestEnv()
	if err == nil {
		err = run(cmd, rest, env)
	}
	if err == nil {
		return 0
	}
	code := ExitCode(err)
	msg := term.Line(err.Error())
	if asJSON {
		fmt.Fprintln(env.Stdout, string(op.MustEncode(op.Obj{{K: "error", V: ErrorCode(err)}, {K: "message", V: msg}})))
	}
	var u usageErr
	if errors.As(err, &u) {
		fmt.Fprintln(env.Stderr, Usage)
	}
	fmt.Fprintf(env.Stderr, "harness tickets %s: %s\n", term.Line(cmd), msg)
	return code
}

func run(cmd string, args []string, env Env) error {
	switch cmd {
	case "init":
		return cmdInit(args, env)
	case "new":
		return cmdNew(args, env)
	case "list":
		return cmdList(args, env)
	case "show":
		return cmdShow(args, env)
	case "move":
		return cmdMove(args, env)
	case "comment":
		return cmdComment(args, env)
	case "edit":
		return cmdEdit(args, env)
	case "label":
		return cmdLabel(args, env)
	case "status":
		return cmdStatus(args, env)
	case "writers":
		return cmdWriters(args, env)
	case "rebuild":
		return cmdRebuild(args, env)
	case "export":
		return cmdExport(args, env)
	case "sync-state":
		return cmdSyncState(args, env)
	case "bind":
		return cmdBind(args, env)
	case "trust-writer":
		return cmdTrustWriter(args, env)
	case "block-writer":
		return cmdBlockWriter(args, env)
	case "travel":
		return cmdTravel(args, env)
	case "fetch", "push", "sync", "import":
		return usagef("%s is not part of Phase 0a (local-only ledger)", cmd)
	}
	return usagef("unknown command %q", cmd)
}

func open(p parsed, env Env) (*ledger.Ledger, error) {
	l, err := ledger.Open(ledger.Location{Cwd: env.Cwd, Slug: p.get("slug")})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func warn(l *ledger.Ledger, env Env) {
	for _, w := range l.Warnings() {
		fmt.Fprintf(env.Stderr, "harness tickets: warning: %s\n", term.Line(w))
	}
}

func emit(env Env, asJSON bool, doc op.Obj, human string) {
	if asJSON {
		fmt.Fprintln(env.Stdout, string(op.MustEncode(doc)))
		return
	}
	fmt.Fprint(env.Stdout, human)
}

func nowView(l *ledger.Ledger) (*fold.View, error) {
	v, err := l.View()
	if err != nil {
		return nil, err
	}
	now, err := ledger.Now()
	if err != nil {
		return nil, err
	}
	return fold.Annotate(v, now), nil
}

func readBody(p parsed, env Env) (string, bool, error) {
	if p.has("body") && p.has("body-file") {
		return "", false, usagef("give --body or --body-file, not both")
	}
	if p.has("body") {
		return p.get("body"), true, nil
	}
	if !p.has("body-file") {
		return "", false, nil
	}
	f := p.get("body-file")
	var r io.Reader
	if f == "-" {
		r = env.Stdin
	} else {
		fh, err := os.Open(f)
		if err != nil {
			return "", false, usagef("cannot read --body-file")
		}
		defer fh.Close()
		r = fh
	}
	b, err := io.ReadAll(io.LimitReader(r, op.MaxBodyBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > op.MaxBodyBytes {
		return "", false, usagef("body exceeds %d bytes", op.MaxBodyBytes)
	}
	return string(b), true, nil
}

func cmdInit(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"name": true, "no-repo": false, "from-mirror": false}))
	if err != nil {
		return err
	}
	if len(p.pos) > 0 {
		return usagef("init takes no positional arguments")
	}
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	l, err := ledger.Init(ledger.Location{Cwd: env.Cwd}, ledger.InitOptions{Slug: p.get("slug"), Name: p.get("name"),
		NoRepo: p.has("no-repo"), FromMirror: p.has("from-mirror"), Actor: actor})
	if err != nil {
		return err
	}
	defer l.Close()
	warn(l, env)
	v, err := nowView(l)
	if err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "project", V: l.Project}, {K: "slug", V: l.Slug}, {K: "repo_less", V: !l.InRepo},
		{K: "tickets", V: len(v.Tickets)}}, fmt.Sprintf("initialized ledger %s (%s); local-only\n", l.Slug, l.Project))
	return nil
}

func validStatus(v *fold.View, s string) (fold.Status, error) {
	st, ok := v.StatusByKey(s)
	if !ok {
		keys := make([]string, len(v.Statuses))
		for i, x := range v.Statuses {
			keys[i] = x.Key
		}
		return st, usagef("unknown status %q (one of %s)", s, strings.Join(keys, ", "))
	}
	return st, nil
}

func normLabels(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, l := range in {
		for _, part := range strings.Split(l, ",") {
			d := op.LabelDisplay(part)
			if d == "" {
				continue
			}
			if !op.ValidLabel(d) {
				return nil, usagef("invalid label (1-%d characters, no control characters or commas)", op.MaxLabelRunes)
			}
			if k := op.LabelKey(d); !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	if len(out) > op.MaxLabels {
		return nil, usagef("at most %d labels", op.MaxLabels)
	}
	return out, nil
}

func writeResult(env Env, p parsed, l *ledger.Ledger, res *ledger.Result, ticketID string, human string) error {
	warn(l, env)
	ids := make([]any, len(res.Ops))
	for i, o := range res.Ops {
		ids[i] = op.Obj{{K: "id", V: o.ID}, {K: "kind", V: o.Kind}}
	}
	doc := op.Obj{{K: "ops", V: ids}, {K: "writer", V: res.Writer}}
	if ticketID != "" {
		now, _ := ledger.Now()
		v := fold.Annotate(res.View, now)
		if t := v.FindTicket(ticketID); t != nil {
			doc = append(doc, op.Field{K: "ticket", V: TicketSummary(t)})
			human = strings.ReplaceAll(human, "{handle}", v.Slug+"#"+t.Handle)
		}
	}
	emit(env, p.has("json"), doc, human)
	return nil
}

func cmdNew(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"title": true, "body": true, "body-file": true, "type": true, "priority": true,
		"label": true, "status": true}))
	if err != nil {
		return err
	}
	if len(p.pos) > 0 {
		return usagef("new takes no positional arguments; use --title")
	}
	title := p.get("title")
	if !op.ValidTitle(title) {
		return usagef("--title is required (one line, at most %d bytes)", op.MaxTitleBytes)
	}
	body, _, err := readBody(p, env)
	if err != nil {
		return err
	}
	typ, prio := orDefault(p.get("type"), "task"), orDefault(p.get("priority"), "medium")
	if !op.Types[typ] || !op.Priorities[prio] {
		return usagef("invalid --type or --priority")
	}
	labels, err := normLabels(p.all("label"))
	if err != nil {
		return err
	}
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	status := p.get("status")
	d := op.Draft{Actor: actor, Kind: op.KindTicketCreate}
	res, err := l.Append([]op.Draft{d}, ledger.AppendOptions{RedactSecrets: p.has("redact-secrets")}, func(v *fold.View, ds []op.Draft) error {
		st := v.Statuses[0]
		for _, x := range v.Statuses {
			if x.Category == "unstarted" {
				st = x
				break
			}
		}
		if status != "" {
			var err error
			if st, err = validStatus(v, status); err != nil {
				return err
			}
		}
		ds[0].Payload = op.TicketCreate(title, body, typ, prio, labels, st.Key, st.Category)
		return nil
	})
	if err != nil {
		return err
	}
	return writeResult(env, p, l, res, res.Ops[0].Ticket, "created Ledger {handle}\n")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// resolveFor resolves a handle against a view (for write checks).
func resolveFor(v *fold.View, handle string) (*fold.Ticket, error) { return Resolve(v, handle, 0) }

func oneHandle(p parsed, n int, what string) (string, error) {
	if len(p.pos) != n {
		return "", usagef("usage: harness tickets %s", what)
	}
	return p.pos[0], nil
}

func cmdMove(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	handle, err := oneHandle(p, 2, "move <handle> <status>")
	if err != nil {
		return err
	}
	to := p.pos[1]
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	var tid string
	res, err := l.Append([]op.Draft{{Actor: actor, Kind: op.KindStatusSet}}, ledger.AppendOptions{}, func(v *fold.View, ds []op.Draft) error {
		t, err := resolveFor(v, handle)
		if err != nil {
			return err
		}
		st, err := validStatus(v, to)
		if err != nil {
			return err
		}
		tid = t.ID
		ds[0].Ticket, ds[0].Payload = t.ID, op.StatusSet(t.Status, st.Key, st.Category)
		return nil
	})
	if err != nil {
		return err
	}
	return writeResult(env, p, l, res, tid, "moved Ledger {handle} to "+to+"\n")
}

func cmdComment(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"body": true, "body-file": true}))
	if err != nil {
		return err
	}
	handle, err := oneHandle(p, 1, "comment <handle> --body B")
	if err != nil {
		return err
	}
	body, ok, err := readBody(p, env)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(body) == "" {
		return usagef("comment needs a non-empty --body or --body-file")
	}
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	var tid string
	d := op.Draft{Actor: actor, Kind: op.KindComment, Payload: op.Comment("", body)}
	res, err := l.Append([]op.Draft{d}, ledger.AppendOptions{RedactSecrets: p.has("redact-secrets")}, func(v *fold.View, ds []op.Draft) error {
		t, err := resolveFor(v, handle)
		if err != nil {
			return err
		}
		tid, ds[0].Ticket = t.ID, t.ID
		return nil
	})
	if err != nil {
		return err
	}
	return writeResult(env, p, l, res, tid, "commented on Ledger {handle}\n")
}

func cmdEdit(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"title": true, "body": true, "body-file": true, "priority": true, "type": true}))
	if err != nil {
		return err
	}
	handle, err := oneHandle(p, 1, "edit <handle> [--title T] [--body B] [--priority P] [--type T]")
	if err != nil {
		return err
	}
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	var drafts []op.Draft
	add := func(field, value string, ok bool) {
		if ok {
			drafts = append(drafts, op.Draft{Actor: actor, Kind: op.KindFieldSet, Payload: op.FieldSet(field, value)})
		}
	}
	if p.has("title") && !op.ValidTitle(p.get("title")) {
		return usagef("invalid --title")
	}
	if p.has("priority") && !op.Priorities[p.get("priority")] || p.has("type") && !op.Types[p.get("type")] {
		return usagef("invalid --priority or --type")
	}
	body, hasBody, err := readBody(p, env)
	if err != nil {
		return err
	}
	add("title", p.get("title"), p.has("title"))
	add("body", body, hasBody)
	add("priority", p.get("priority"), p.has("priority"))
	add("type", p.get("type"), p.has("type"))
	if len(drafts) == 0 {
		return usagef("edit needs at least one of --title, --body, --body-file, --priority, --type")
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	var tid string
	res, err := l.Append(drafts, ledger.AppendOptions{RedactSecrets: p.has("redact-secrets")}, func(v *fold.View, ds []op.Draft) error {
		t, err := resolveFor(v, handle)
		if err != nil {
			return err
		}
		tid = t.ID
		for i := range ds {
			ds[i].Ticket = t.ID
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeResult(env, p, l, res, tid, "edited Ledger {handle}\n")
}

func cmdLabel(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"add": true, "remove": true}))
	if err != nil {
		return err
	}
	handle, err := oneHandle(p, 1, "label <handle> [--add L]... [--remove L]...")
	if err != nil {
		return err
	}
	adds, err := normLabels(p.all("add"))
	if err != nil {
		return err
	}
	rems, err := normLabels(p.all("remove"))
	if err != nil {
		return err
	}
	if len(adds)+len(rems) == 0 {
		return usagef("label needs --add or --remove")
	}
	actor, err := DefaultActor(env.Getenv, p.get("actor-label"))
	if err != nil {
		return err
	}
	var drafts []op.Draft
	for _, a := range adds {
		drafts = append(drafts, op.Draft{Actor: actor, Kind: op.KindLabelAdd, Payload: op.Label(a)})
	}
	for _, r := range rems {
		drafts = append(drafts, op.Draft{Actor: actor, Kind: op.KindLabelRemove, Payload: op.Label(r)})
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	var tid string
	res, err := l.Append(drafts, ledger.AppendOptions{RedactSecrets: p.has("redact-secrets")}, func(v *fold.View, ds []op.Draft) error {
		t, err := resolveFor(v, handle)
		if err != nil {
			return err
		}
		tid = t.ID
		for i := range ds {
			ds[i].Ticket = t.ID
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeResult(env, p, l, res, tid, "labelled Ledger {handle}\n")
}

func cmdList(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"status": true, "label": true}))
	if err != nil {
		return err
	}
	if len(p.pos) > 0 {
		return usagef("list takes no positional arguments")
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	v, err := nowView(l)
	if err != nil {
		return err
	}
	warn(l, env)
	status, label := p.get("status"), p.get("label")
	filter := func(t *fold.Ticket) bool {
		if status != "" && t.Status != status {
			return false
		}
		if label != "" {
			k := op.LabelKey(label)
			for _, x := range t.Labels {
				if op.LabelKey(x) == k {
					return true
				}
			}
			return false
		}
		return true
	}
	var rows []*fold.Ticket
	for i := range v.Tickets {
		if filter(&v.Tickets[i]) {
			rows = append(rows, &v.Tickets[i])
		}
	}
	emit(env, p.has("json"), ListJSON(v, filter), humanList(v, rows))
	return nil
}

// versionLess compares dotted numeric versions.
func versionLess(a, b string) (bool, error) {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pb) != 3 {
		return false, usagef("--min-version must be MAJOR.MINOR.PATCH")
	}
	for i := 0; i < 3; i++ {
		x, err1 := strconv.Atoi(pa[i])
		y, err2 := strconv.Atoi(pb[i])
		if err1 != nil || err2 != nil || y < 0 {
			return false, usagef("--min-version must be MAJOR.MINOR.PATCH")
		}
		if x != y {
			return x < y, nil
		}
	}
	return false, nil
}

func cmdShow(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"history": false, "as-of": true, "min-version": true}))
	if err != nil {
		return err
	}
	if p.has("min-version") {
		less, err := versionLess(ledger.Version, p.get("min-version"))
		if err != nil {
			return err
		}
		if less {
			return usagef("ledger version %s is older than the required %s", ledger.Version, p.get("min-version"))
		}
	}
	handle, err := oneHandle(p, 1, "show <handle>")
	if err != nil {
		return err
	}
	var asOf int64
	if p.has("as-of") {
		if asOf, err = strconv.ParseInt(p.get("as-of"), 10, 64); err != nil || asOf <= 0 {
			return usagef("--as-of must be a positive millisecond timestamp")
		}
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	v, err := nowView(l)
	if err != nil {
		return err
	}
	warn(l, env)
	t, err := Resolve(v, handle, asOf)
	if err != nil {
		return err
	}
	emit(env, p.has("json"), ShowJSON(v, t), humanShow(v, t, p.has("history")))
	return nil
}

// CurrentWriter returns this process's writer id without minting (empty when it has not written yet).
func currentWriter(l *ledger.Ledger) string { return l.CurrentWriterID() }

func cmdStatus(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"agent-snippet": false}))
	if err != nil {
		return err
	}
	if p.has("agent-snippet") {
		if p.has("json") {
			emit(env, true, op.Obj{{K: "snippet", V: AgentSnippet}}, "")
			return nil
		}
		fmt.Fprintln(env.Stdout, AgentSnippet)
		return nil
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	fresh := l.CacheFresh()
	v, err := nowView(l)
	if err != nil {
		return err
	}
	warn(l, env)
	me := currentWriter(l)
	emit(env, p.has("json"), StatusJSON(l, v, me, fresh), humanStatus(l, v, me, fresh))
	return nil
}

func cmdWriters(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"show": true}))
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	v, err := nowView(l)
	if err != nil {
		if errors.Is(err, ledger.ErrRefused) {
			return writersWithoutRoot(p, l, env, err) // an adopted ledger whose writers are not trusted yet
		}
		return err
	}
	if p.has("show") {
		w := p.get("show")
		info := v.WriterByID(w)
		if info == nil {
			return wrapNF("no writer %s", term.Line(w))
		}
		rows := []op.Obj{}
		var b strings.Builder
		fmt.Fprintf(&b, "writer %s class %s, %d ops (pending review; not folded unless self or trusted)\n", w, info.Class, info.Ops)
		for _, x := range v.Pending {
			if x.Writer != w {
				continue
			}
			rows = append(rows, op.Obj{{K: "op", V: x.Op}, {K: "kind", V: x.Kind}, {K: "wall_ms", V: x.WallMs},
				{K: "claimed_actor", V: term.Line(x.Actor)}, {K: "ticket", V: x.Ticket}, {K: "preview", V: term.Line(x.Title)}})
			fmt.Fprintf(&b, "  %s %s claimed: %s %s %s\n", when(x.WallMs), x.Kind, term.Line(x.Actor), x.Ticket, term.Line(x.Title))
		}
		review := op.Obj{}
		if ops, digest, _, rerr := l.WriterReview(w); rerr == nil {
			texts := []string{}
			for _, o := range ops {
				t := string(o.Raw)
				if len(t) > 2048 {
					t = t[:2048] + "..."
				}
				texts = append(texts, s(t))
				fmt.Fprintf(&b, "  op %s\n", s(term.Line(t)))
			}
			fmt.Fprintf(&b, "review digest %s (covers all %d ops above; trust-writer %s --reviewed DIGEST)\n", digest, len(ops), w)
			review = op.Obj{{K: "review_digest", V: digest}, {K: "ops_text", V: texts}}
		}
		doc := op.Obj{{K: "writer", V: w}, {K: "class", V: info.Class}, {K: "ops", V: info.Ops},
			{K: "rejected", V: term.Line(info.Rejected)}, {K: "pending", V: rows}}
		emit(env, p.has("json"), append(doc, review...), b.String())
		return nil
	}
	ws := []op.Obj{}
	var b strings.Builder
	for _, w := range v.Writers {
		ws = append(ws, op.Obj{{K: "id", V: w.ID}, {K: "class", V: w.Class}, {K: "ops", V: w.Ops},
			{K: "first_ms", V: w.FirstMs}, {K: "last_ms", V: w.LastMs}, {K: "rejected", V: term.Line(w.Rejected)}})
		fmt.Fprintf(&b, "%s %-10s %4d ops %s\n", w.ID, w.Class, w.Ops, term.Line(w.Rejected))
	}
	emit(env, p.has("json"), op.Obj{{K: "project", V: v.Project}, {K: "writers", V: ws}}, b.String())
	return nil
}

func cmdRebuild(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	v, err := l.Rebuild()
	if err != nil {
		return err
	}
	emit(env, p.has("json"), op.Obj{{K: "project", V: v.Project}, {K: "tickets", V: len(v.Tickets)}},
		fmt.Sprintf("rebuilt view: %d tickets\n", len(v.Tickets)))
	return nil
}

func cmdExport(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"format": true, "out": true, "since-bound": false}))
	if err != nil {
		return err
	}
	format := orDefault(p.get("format"), "md")
	if format != "md" && format != "json" && format != "goodqa-import" {
		return usagef("--format must be md, json or goodqa-import")
	}
	if p.has("since-bound") && format != "goodqa-import" {
		return usagef("--since-bound applies to --format goodqa-import")
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	var body string
	if format == "goodqa-import" {
		if body, err = exportImport(p, env, l); err != nil {
			return err
		}
	} else {
		v, err := nowView(l)
		if err != nil {
			return err
		}
		body = exportMarkdown(v)
		if format == "json" {
			body = exportJSON(v)
		}
	}
	if !p.has("out") {
		_, err := io.WriteString(env.Stdout, body)
		return err
	}
	out := p.get("out")
	if !filepath.IsAbs(out) {
		out = filepath.Join(env.Cwd, out)
	}
	return publishNew(out, []byte(body), env)
}
