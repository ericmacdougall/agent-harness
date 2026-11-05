package ledger

import (
	"sync"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

// Several checkouts of one project share mirror-writers.json. Every registration that returned nil must be
// in the registry afterwards: a lost entry makes that writer's acknowledged ops stop counting as self.
func TestRegisterWriterConcurrentCheckoutsLoseNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	const n = 24
	ids := make([]string, n)
	for i := range ids {
		id, err := op.NewID(op.PrefixWriter, 1767225600000+int64(i))
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := &Ledger{Project: "prj_testregistry"}
			<-start
			errs[i] = l.registerWriter(ids[i], "lease-"+ids[i])
		}(i)
	}
	close(start)
	wg.Wait()
	reg := (&Ledger{Project: "prj_testregistry"}).registry()
	for i, id := range ids {
		if errs[i] == nil && reg[id] == "" {
			t.Errorf("writer %d registered without error but is missing from the registry (%d of %d present)", i, len(reg), n)
		}
	}
}
