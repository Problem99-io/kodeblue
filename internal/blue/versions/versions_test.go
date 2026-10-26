package versions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const ubuntuCSV = `version,codename,series,created,release,eol,eol-server,eol-esm,eol-legacy
22.04 LTS,Jammy Jellyfish,jammy,2021-10-14,2022-04-21,2027-06-01,2027-06-01,2032-04-21,2037-04-21
24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25,2039-04-28
`

const aptSim = `NOTE: This is only a simulation!
Inst motd-news-config [13ubuntu10.4] (13ubuntu10.5 Ubuntu:24.04/noble-updates [all])
Inst openssh-server [1:9.6p1-3ubuntu13.14] (1:9.6p1-3ubuntu13.15 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) []
Inst linux-image-7.0.0-31-generic (7.0.0-31.31 Ubuntu:24.04/noble-security [amd64])
Conf openssh-server (1:9.6p1-3ubuntu13.15 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`

func TestParseAptSimulation(t *testing.T) {
	u := ParseAptSimulation(aptSim)
	if len(u) != 3 {
		t.Fatalf("got %d updates: %+v", len(u), u)
	}
	if u[0].Security || u[0].From != "13ubuntu10.4" || u[0].To != "13ubuntu10.5" {
		t.Errorf("plain update read wrong: %+v", u[0])
	}
	if !u[1].Security || u[1].Package != "openssh-server" || u[1].From != "1:9.6p1-3ubuntu13.14" {
		t.Errorf("security update read wrong: %+v", u[1])
	}
	if !u[2].Security || u[2].From != "" || u[2].To != "7.0.0-31.31" {
		t.Errorf("new package read wrong: %+v", u[2])
	}
}

func TestSupportEnds(t *testing.T) {
	eol, esm := SupportEnds(ubuntuCSV, "24.04", "noble")
	if eol.Format("2006-01-02") != "2029-05-31" || esm.Format("2006-01-02") != "2034-04-25" {
		t.Errorf("noble: eol %v esm %v", eol, esm)
	}
	eol, _ = SupportEnds(ubuntuCSV, "", "jammy")
	if eol.Format("2006-01-02") != "2027-06-01" {
		t.Errorf("by codename: %v", eol)
	}
	if eol, _ := SupportEnds(ubuntuCSV, "26.10", "zesty"); !eol.IsZero() {
		t.Errorf("unknown release matched: %v", eol)
	}
}

func TestTakeAndText(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/os-release", "PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n")
	write("/usr/share/distro-info/ubuntu.csv", ubuntuCSV)
	write("/proc/sys/kernel/osrelease", "5.15.0-100-generic\n")
	write("/var/run/reboot-required", "*** System restart required ***\n")
	write("/var/run/reboot-required.pkgs", "linux-base\nlinux-base\n")
	write("/var/lib/dpkg/status", "")
	write("/var/lib/apt/lists/archive_InRelease", "")
	old := time.Now().Add(-5 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(root, "/var/lib/apt/lists/archive_InRelease"), old, old)

	r := Take(context.Background(), Env{Root: root}, []string{"traefik:v3.7.15"})
	if r.VersionID != "22.04" || r.Kernel != "5.15.0-100-generic" || !r.RebootRequired || len(r.RebootFor) != 1 {
		t.Fatalf("report: %+v", r)
	}
	// Past the end of standard support, with stale package lists.
	txt := r.Text(time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{"Ubuntu 22.04.5 LTS", "standard support ENDED 2027-06-01", "until 2032-04-21", "REBOOT is pending", "STALE", "traefik:v3.7.15"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text misses %q:\n%s", want, txt)
		}
	}
	// On this host, updates come from apt-get -s.
	r = Take(context.Background(), Env{Run: func(ctx context.Context, argv ...string) ([]byte, error) {
		if strings.Join(argv, " ") != "apt-get -s -q dist-upgrade" {
			t.Errorf("ran %v", argv)
		}
		return []byte(aptSim), nil
	}}, nil)
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil && len(r.Security()) != 2 {
		t.Errorf("security updates: %+v", r.Updates)
	}
}
