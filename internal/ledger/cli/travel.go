package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/term"
)

func consentRefusal(err error) error {
	var ce *ledger.ConsentError
	if errors.As(err, &ce) {
		return &codedErr{kind: errRefusedKind, msg: ce.Error()}
	}
	var se *ledger.SecretError
	if errors.As(err, &se) {
		return &codedErr{kind: ledger.ErrSecret, msg: term.Line(err.Error())}
	}
	return err
}

func cmdTravel(args []string, env Env) error {
	if len(args) == 0 {
		return usagef("usage: travel enable|status|push|fetch")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "enable":
		return travelEnable(rest, env)
	case "status":
		return travelStatus(rest, env)
	case "push":
		return travelPush(rest, env)
	case "fetch":
		return travelFetch(rest, env)
	}
	return usagef("unknown travel command %q (enable, status, push, fetch)", sub)
}

func travelEnable(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"remote": true, "yes-share": true, "use-git-credentials": false}))
	if err != nil {
		return err
	}
	if !p.has("remote") || len(p.pos) > 0 {
		return usagef("usage: travel enable --remote NAME [--yes-share TOKEN]")
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := l.TravelEnable(p.get("remote"), p.get("yes-share"), p.has("use-git-credentials")); err != nil {
		return consentRefusal(err)
	}
	emit(env, p.has("json"), op.Obj{{K: "travel", V: "enabled"}, {K: "remote", V: p.get("remote")}},
		fmt.Sprintf("travel enabled for remote %s (push and fetch are explicit commands)\n", term.Line(p.get("remote"))))
	return nil
}

func travelStatus(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	c, ok, ws, err := l.TravelStatus()
	if err != nil {
		return err
	}
	remote := ""
	if c != nil {
		remote = c.Remote
	}
	rows := []op.Obj{}
	var b strings.Builder
	fmt.Fprintf(&b, "remote %q consent %v\n", term.Line(remote), ok)
	for _, w := range ws {
		rows = append(rows, op.Obj{{K: "writer", V: w.ID}, {K: "class", V: w.Class}, {K: "ops", V: w.Ops},
			{K: "unpushed", V: w.Unpushed}, {K: "bytes", V: w.Bytes}})
		fmt.Fprintf(&b, "%s %-10s %5d ops %7d bytes unpushed %d\n", w.ID, w.Class, w.Ops, w.Bytes, w.Unpushed)
	}
	pushed, fetched := int64(0), int64(0)
	if c != nil {
		pushed, fetched = c.PushedMs, c.FetchedMs
	}
	emit(env, p.has("json"), op.Obj{{K: "remote", V: remote}, {K: "consent", V: ok}, {K: "enabled", V: c != nil},
		{K: "credentials", V: c != nil && c.Credentials}, {K: "pushed_ms", V: pushed}, {K: "fetched_ms", V: fetched}, {K: "writers", V: rows}}, b.String())
	return nil
}

func travelPush(args []string, env Env) error {
	p, err := parseArgs(args, common)
	if err != nil {
		return err
	}
	l, err := open(p, env)
	if err != nil {
		return err
	}
	defer l.Close()
	res, err := l.TravelPush()
	if err != nil {
		return consentRefusal(err)
	}
	emit(env, p.has("json"), op.Obj{{K: "pushed", V: res.Refs}},
		fmt.Sprintf("pushed %d writer ref(s)\n", len(res.Refs)))
	return nil
}

func travelFetch(args []string, env Env) error {
	p, err := parseArgs(args, merge(spec{"adopt": false, "remote": true, "yes-share": true, "use-git-credentials": false}))
	if err != nil {
		return err
	}
	var l *ledger.Ledger
	var res *ledger.FetchResult
	if p.has("adopt") {
		if !p.has("remote") {
			return usagef("usage: travel fetch --adopt --remote NAME [--yes-share TOKEN]")
		}
		l, res, err = ledger.TravelAdopt(ledger.Location{Cwd: env.Cwd}, p.get("remote"), p.get("yes-share"), p.get("slug"), p.has("use-git-credentials"))
	} else {
		if l, err = open(p, env); err == nil {
			res, err = l.TravelFetch()
		}
	}
	if err != nil {
		if l != nil {
			l.Close()
		}
		return consentRefusal(err)
	}
	defer l.Close()
	warn(l, env)
	rej := []op.Obj{}
	keys := make([]string, 0, len(res.Rejected))
	for k := range res.Rejected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, w := range res.Accepted {
		fmt.Fprintf(&b, "fetched %s (unverified until trusted)\n", w)
	}
	for _, k := range keys {
		rej = append(rej, op.Obj{{K: "ref", V: term.Line(k)}, {K: "reason", V: term.Line(res.Rejected[k])}})
		fmt.Fprintf(&b, "rejected %s: %s\n", term.Line(k), term.Line(res.Rejected[k]))
	}
	if p.has("adopt") {
		b.WriteString("adopted this ledger. Review each writer with `harness tickets writers --show w_...` and trust it with `trust-writer w_... --reviewed DIGEST`.\n")
	}
	emit(env, p.has("json"), op.Obj{{K: "project", V: res.Project}, {K: "accepted", V: res.Accepted},
		{K: "skipped", V: res.Skipped}, {K: "rejected", V: rej}}, b.String())
	return nil
}
