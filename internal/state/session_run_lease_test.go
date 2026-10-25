package state

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestSessionRunLeaseSurvivesAnotherConnectionAndRecoversProcessExit(t *testing.T) {
	name := filepath.Join(t.TempDir(), "shared.db")
	db, err := NewDB(name)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	sessions := NewSessionRepo(db)
	for _, id := range []internal.SessionID{"target", "other"} {
		if err := sessions.Create(&internal.Session{ID: id, Status: internal.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	runs := NewRunRepo(db)
	for _, row := range []*internal.Run{
		{ID: "orphan", SessionID: "target", Status: internal.RunRunning, CreatedAt: time.Now()},
		{ID: "untouched", SessionID: "other", Status: internal.RunRunning, CreatedAt: time.Now()},
	} {
		if err := runs.Create(row); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSessionRunLeaseProcessHelper$")
	cmd.Env = append(os.Environ(), "KODEBLUE_TEST_RUN_LEASE_DB="+name)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if ready, err := bufio.NewReader(out).ReadString('\n'); err != nil || ready != "locked\n" {
		t.Fatalf("child readiness: %q, %v", ready, err)
	}
	if lease, err := runs.TryAcquireSessionRunLease("target"); err != nil || lease != nil {
		t.Fatalf("stole live process lease: %#v, %v", lease, err)
	}
	other, err := runs.TryAcquireSessionRunLease("other")
	if err != nil || other == nil {
		t.Fatalf("unrelated session blocked: %#v, %v", other, err)
	}
	other.Release()
	if row, _ := runs.Get("orphan"); row.Status != internal.RunRunning {
		t.Fatal("live owner's row changed")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	secondDB, err := NewDB(name)
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()
	second := NewRunRepo(secondDB)
	lease, err := second.TryAcquireSessionRunLease("target")
	if err != nil || lease == nil {
		t.Fatalf("kernel did not release exited process lease: %#v, %v", lease, err)
	}
	defer lease.Release()
	recovered, err := second.RecoverOrphanedSessionRuns(lease)
	if err != nil || len(recovered) != 1 || recovered[0] != "orphan" {
		t.Fatalf("recovery = %#v, %v", recovered, err)
	}
	if row, _ := runs.Get("orphan"); row.Status != internal.RunFailed || row.CompletedAt == nil {
		t.Fatal("orphan not terminal")
	}
	if row, _ := runs.Get("untouched"); row.Status != internal.RunRunning {
		t.Fatal("another session was changed")
	}
	lease.Release()
	if _, err := second.RecoverOrphanedSessionRuns(lease); err == nil {
		t.Fatal("closed lease authorized recovery")
	}
}

func TestSessionRunLeaseProcessHelper(t *testing.T) {
	name := os.Getenv("KODEBLUE_TEST_RUN_LEASE_DB")
	if name == "" {
		return
	}
	db, err := NewDB(name)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewRunRepo(db).TryAcquireSessionRunLease("target")
	if err != nil || lease == nil {
		t.Fatalf("child lease: %#v, %v", lease, err)
	}
	_, _ = os.Stdout.WriteString("locked\n")
	for {
		time.Sleep(time.Hour)
	}
}
