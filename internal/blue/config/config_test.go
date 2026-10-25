package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateEngineDir(t *testing.T) {
	c := Default()
	c.Server.StateDir = t.TempDir()
	old := filepath.Join(c.Server.StateDir, "kodecode")
	if err := os.Mkdir(old, 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(old, "kodecode.db"), []byte("db"), 0o600)
	os.WriteFile(filepath.Join(old, "config.toml"), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(old, "kodecode.db.run-locks"), 0o750)
	if err := c.MigrateEngineDir(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(c.EngineDir(), "engine.db")); string(b) != "db" {
		t.Fatal("database not moved")
	}
	for _, n := range []string{"config.toml", "engine.db.run-locks"} {
		if _, err := os.Stat(filepath.Join(c.EngineDir(), n)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old dir left behind")
	}
	if err := c.MigrateEngineDir(); err != nil { // nothing to do
		t.Fatal(err)
	}
}
