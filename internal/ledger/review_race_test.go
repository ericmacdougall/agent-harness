package ledger_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
)

func TestWriterReviewConcurrentDoesNotReleaseHeldOps(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "review-race")
	handle := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	wid := b.jsonOK(b.repo, nil, "writers")["writers"].([]any)[0].(map[string]any)["id"].(string)
	digest := b.jsonOK(b.repo, nil, "writers", "--show", wid)["review_digest"].(string)
	b.ok(b.repo, nil, "trust-writer", wid, "--reviewed", digest)
	a.ok(a.repo, nil, "comment", handle, "--body", "unreviewed")
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch")

	t.Setenv("HOME", b.home) // the CLI helpers set HOME per command; in-process reads need it too
	l, err := ledger.Open(ledger.Location{Cwd: b.repo})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	in, err := l.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if in.Held[wid] != 1 {
		t.Fatalf("test setup has %d held ops, want 1", in.Held[wid])
	}
	reviewedOps := 0
	for _, ref := range in.Refs {
		if ref.Writer == wid {
			reviewedOps = len(ref.Ops)
		}
	}
	if reviewedOps == 0 {
		t.Fatal("trusted writer has no reviewed prefix")
	}
	if _, err := l.View(); err != nil { // initialize the cache key before concurrent readers
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for range 20 {
			ops, _, _, err := l.WriterReview(wid)
			if err != nil {
				errs <- err
				return
			}
			if len(ops) != reviewedOps+1 {
				errs <- fmt.Errorf("full review returned %d ops, want %d", len(ops), reviewedOps+1)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range 20 {
			in, err := l.Snapshot()
			if err != nil {
				errs <- err
				return
			}
			if in.Held[wid] != 1 {
				errs <- fmt.Errorf("normal snapshot released the unreviewed op")
				return
			}
			v, err := l.Rebuild()
			if err != nil {
				errs <- err
				return
			}
			writer := v.WriterByID(wid)
			if writer == nil || writer.Ops != reviewedOps || len(v.Tickets) != 1 || len(v.Tickets[0].Comments) != 0 {
				errs <- fmt.Errorf("normal view contains unreviewed ops: writer=%#v tickets=%#v", writer, v.Tickets)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	v, err := l.View() // read the cache populated by the concurrent normal views
	if err != nil {
		t.Fatal(err)
	}
	if writer := v.WriterByID(wid); writer == nil || writer.Ops != reviewedOps || len(v.Tickets[0].Comments) != 0 {
		t.Fatalf("normal cache contains unreviewed ops: writer=%#v tickets=%#v", writer, v.Tickets)
	}
	if !l.CacheFresh() {
		t.Fatal("normal view cache is not fresh")
	}
}
