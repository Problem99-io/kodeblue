package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestReplaceSection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kodeblue.toml")
	orig := "# policy\n[server]\nname = \"web-1\"\n\n[hub]\nurl = \"https://old\"\npin = \"x\"\n\n[response]\nmode = \"recommend\" # keep\n"
	if err := os.WriteFile(p, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := replaceSection(p, "hub", "[hub]\nurl = \"https://new\"\n"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if strings.Count(s, "[hub]") != 1 || strings.Contains(s, "https://old") || strings.Contains(s, `pin = "x"`) {
		t.Fatalf("old [hub] not replaced:\n%s", s)
	}
	if !strings.Contains(s, `mode = "recommend" # keep`) || !strings.Contains(s, "# policy") {
		t.Fatalf("other sections changed:\n%s", s)
	}
	var cfg struct {
		Hub      struct{ URL string } `toml:"hub"`
		Response struct{ Mode string }
	}
	if _, err := toml.Decode(s, &cfg); err != nil || cfg.Hub.URL != "https://new" || cfg.Response.Mode != "recommend" {
		t.Fatalf("result does not parse as intended: %v %+v", err, cfg)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", st.Mode().Perm())
	}
}
