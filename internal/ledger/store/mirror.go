package store

import (
	"errors"
	"path/filepath"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
)

// PushMirror pushes one own ref to the local bare mirror (fast-forward only) and verifies the result by
// reading the mirror ref directly, so a URL rewrite or a silent push failure is never reported as success.
//
// Local transports clear GIT_CONFIG_COUNT for the receiving side, so the receive-pack is started with its
// own -c core.hooksPath (the mirror also has core.hooksPath set at creation): no hook runs on either side.
func (g *Git) PushMirror(mirror, ref, want string) error {
	if !filepath.IsAbs(mirror) {
		return errors.New("mirror path must be absolute")
	}
	receive := "git -c core.hooksPath=" + gitx.DevNull + " -c receive.denyNonFastForwards=true receive-pack"
	_, err := g.run(TransportTimeout, nil, nil, "push", "--quiet", "--no-verify", "--porcelain",
		"--receive-pack="+receive, mirror, ref+":"+ref)
	m := &Git{GitDir: mirror}
	got, terr := m.Tip(ref)
	if terr != nil {
		return terr
	}
	if got != want {
		if err != nil {
			return err
		}
		return errors.New("mirror ref does not match after push")
	}
	return nil
}

// FetchFromMirror copies every writer ref of project from the mirror into this repository (used by
// init --from-mirror; refs that already exist must fast-forward).
func (g *Git) FetchFromMirror(mirror, project string) error {
	if !filepath.IsAbs(mirror) {
		return errors.New("mirror path must be absolute")
	}
	spec := RefPrefix + project + "/log/*:" + RefPrefix + project + "/log/*"
	_, err := g.run(TransportTimeout, nil, nil, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head",
		"--upload-pack=git -c core.hooksPath="+gitx.DevNull+" upload-pack", mirror, spec)
	return err
}
