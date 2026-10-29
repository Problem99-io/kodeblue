package store

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloudflareBudgetIsAtomicAndSeparate(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var wg sync.WaitGroup
	var accepted atomic.Int32
	now := time.Now()
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.ReserveCloudflareLookup(now, 10)
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted %d", accepted.Load())
	}
	if len(st.JournalSince(now.Add(-time.Hour), 100)) != 0 {
		t.Fatal("budget polluted journal")
	}
	ok, err := st.ReserveCloudflareLookup(now.Add(time.Minute), 10)
	if !ok || err != nil {
		t.Fatalf("next window: %v %v", ok, err)
	}
}
