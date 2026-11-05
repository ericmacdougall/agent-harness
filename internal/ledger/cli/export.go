package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/term"
	"github.com/ericmacdougall/agent-harness/internal/safefs"
)

// mdEscape keeps untrusted text from forming Markdown structure (links, headings, HTML).
func mdEscape(x string) string {
	r := strings.NewReplacer(`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "<", "&lt;", ">", "&gt;", "#", `\#`, "|", `\|`)
	return r.Replace(term.Sanitize(x))
}

func exportMarkdown(v *fold.View) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ledger %s\n\nProject `%s`, local-only. %d tickets. Claimed actors are unverified metadata.\n", mdEscape(v.Slug), v.Project, len(v.Tickets))
	for i := range v.Tickets {
		t := &v.Tickets[i]
		fmt.Fprintf(&b, "\n## %s#%s %s\n\n", mdEscape(v.Slug), t.Handle, mdEscape(term.Line(t.Title)))
		fmt.Fprintf(&b, "- id: `%s`\n- status: %s (%s)\n- priority: %s\n- type: %s\n- created: %s\n- updated: %s\n",
			t.ID, t.Status, t.Category, t.Priority, t.Type, when(t.CreatedMs), when(t.UpdatedMs))
		if len(t.Labels) > 0 {
			ls := make([]string, len(t.Labels))
			for j, l := range t.Labels {
				ls[j] = mdEscape(l)
			}
			fmt.Fprintf(&b, "- labels: %s\n", strings.Join(ls, ", "))
		}
		if t.Body != "" {
			fmt.Fprintf(&b, "\n%s\n", mdEscape(t.Body))
		}
		if len(t.Comments) > 0 {
			b.WriteString("\n### Comments\n")
			for _, c := range t.Comments {
				fmt.Fprintf(&b, "\n- %s, claimed: %s, writer `%s`\n\n  %s\n", when(c.WallMs), mdEscape(c.Actor), c.Writer,
					strings.ReplaceAll(mdEscape(c.Body), "\n", "\n  "))
			}
		}
		b.WriteString("\n### History\n\n")
		for _, e := range t.History {
			detail := eventDetail(e, func(x string) string { return mdEscape(term.Line(x)) })
			fmt.Fprintf(&b, "- %s `%s`%s (claimed: %s, writer `%s`)\n", when(e.WallMs), e.Kind, detail, mdEscape(e.Actor), e.Writer)
		}
	}
	return b.String()
}

func exportJSON(v *fold.View) string {
	tickets := []op.Obj{}
	for i := range v.Tickets {
		tickets = append(tickets, ShowJSON(v, &v.Tickets[i])[3].V.(op.Obj))
	}
	doc := op.Obj{{K: "project", V: v.Project}, {K: "slug", V: v.Slug}, {K: "travel", V: "local"}, {K: "tickets", V: tickets}}
	return string(op.MustEncode(doc)) + "\n"
}

// publishNew writes a new file (never overwriting, never following a symlink) in an existing directory.
func publishNew(path string, body []byte, env Env) error {
	d, err := safefs.OpenDir(filepath.Dir(path))
	if err != nil {
		return usagef("cannot open the --out directory")
	}
	defer d.Close()
	if err := d.PublishNew(filepath.Base(path), body); err != nil {
		return &codedErr{kind: errRefusedKind, msg: "refusing to write --out (it exists or is unsafe)"}
	}
	fmt.Fprintf(env.Stderr, "exported to %s\n", term.Line(path))
	return nil
}
