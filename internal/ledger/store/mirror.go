package store

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
)

// PushToRepo copies one ref from this HOME mirror (the receiver g is the mirror) into the repository at
// repo, replacing whatever the repository holds there, and verifies the result by reading the repository
// ref directly. The mirror is where own writers append; the repository copy is what travels with it.
//
// The transfer runs as a push from inside the mirror, so only the mirror's own configuration (created by
// init, hooks off) applies: the repository's config, including any url.*.insteadOf or pushInsteadOf
// rewrite, is never consulted for where the data goes. The repository side only runs receive-pack, with
// hooks, auto-gc, non-fast-forward refusal and alternates advertisement off, and core.alternateRefsCommand
// pinned.
func (g *Git) PushToRepo(repo, ref, want string) error {
	if !filepath.IsAbs(repo) || !filepath.IsAbs(g.GitDir) {
		return errors.New("mirror and repository paths must be absolute")
	}
	_, err := g.run(TransportTimeout, nil, nil, "push", "--quiet", "--no-verify", "--porcelain",
		"--receive-pack=git -c core.hooksPath="+gitx.DevNull+" -c receive.autogc=false -c receive.denyNonFastForwards=false"+
			" -c receive.denyDeletes=false -c receive.advertiseAlternates=false -c receive.fsckObjects=false"+
			// receive-pack's connectivity check walks alternates' refs with this command (inherited by its
			// rev-list): pin it to one that lists nothing.
			" -c core.alternateRefsCommand=true receive-pack",
		repo, "+"+ref+":"+ref)
	r := &Git{GitDir: repo}
	got, terr := r.Tip(ref)
	if terr != nil {
		return terr
	}
	if got != want {
		if err != nil {
			return err
		}
		return errors.New("repository ref does not match the mirror after copy")
	}
	return nil
}

// FetchFromMirror copies every writer ref of project from the mirror into this repository (used by
// init --from-mirror; refs that already exist must fast-forward). Every resulting ref must equal the
// mirror's tip, read directly from the mirror, so a rewritten source URL cannot inject other refs.
func (g *Git) FetchFromMirror(mirror, project string) error {
	if !filepath.IsAbs(mirror) {
		return errors.New("mirror path must be absolute")
	}
	m := &Git{GitDir: mirror}
	want, _, err := m.Refs()
	if err != nil {
		return err
	}
	spec := RefPrefix + project + "/log/*:" + RefPrefix + project + "/log/*"
	if _, err := g.run(TransportTimeout, nil, nil, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head",
		"--upload-pack=git -c core.hooksPath="+gitx.DevNull+" upload-pack", mirror, spec); err != nil {
		return err
	}
	got, _, err := g.Refs()
	if err != nil {
		return err
	}
	// Refs the mirror lacks (a collaborator's or a planted ref) are left alone; they fold as unverified.
	prefix := RefPrefix + project + "/log/"
	for name, tip := range want {
		if strings.HasPrefix(name, prefix) && got[name] != tip {
			return errors.New("mirror ref was not restored: " + name)
		}
	}
	return nil
}
