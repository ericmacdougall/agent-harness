package store

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
)

// PushMirror copies one own ref into the local bare mirror (fast-forward only) and verifies the result by
// reading the mirror ref directly, so a silent failure is never reported as success.
//
// The transfer runs as a fetch inside the mirror, so only the mirror's own configuration (created by
// init, hooks off) applies: the repository's config, including any url.*.insteadOf or pushInsteadOf
// rewrite of the mirror path, is never consulted for where the data goes. The repository side only runs
// upload-pack, with hooks off.
func (g *Git) PushMirror(mirror, ref, want string) error {
	if !filepath.IsAbs(mirror) || !filepath.IsAbs(g.GitDir) {
		return errors.New("mirror and repository paths must be absolute")
	}
	m := &Git{GitDir: mirror}
	_, err := m.run(TransportTimeout, nil, nil, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head",
		"--upload-pack=git -c core.hooksPath="+gitx.DevNull+" upload-pack", g.GitDir, ref+":"+ref)
	got, terr := m.Tip(ref)
	if terr != nil {
		return terr
	}
	if got != want {
		if err != nil {
			return err
		}
		return errors.New("mirror ref does not match after copy")
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
	prefix := RefPrefix + project + "/log/"
	for name, tip := range got {
		if strings.HasPrefix(name, prefix) && want[name] != tip {
			return errors.New("restored ref does not match the mirror: " + name)
		}
	}
	for name, tip := range want {
		if strings.HasPrefix(name, prefix) && got[name] != tip {
			return errors.New("mirror ref was not restored: " + name)
		}
	}
	return nil
}
