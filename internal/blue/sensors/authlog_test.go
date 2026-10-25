package sensors

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseAuthLines(t *testing.T) {
	lines := []string{
		"2026-10-18T23:51:26.236536+00:00 web sshd[102]: Accepted publickey for alice from 198.51.100.20 port 50002 ssh2: ED25519 SHA256:abc",
		"2026-10-18T23:51:27+00:00 web sshd[103]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2",
		"2026-10-18T23:51:28+00:00 web sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart shop",
		"2026-10-18T23:51:29+00:00 web su[77]: pam_unix(su:session): session opened for user kodeblue(uid=999) by (uid=0)",
		"Oct 18 23:51:30 web useradd[88]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1",
	}
	ev := parseAuthLines(lines)
	if len(ev) != 5 {
		t.Fatalf("want 5 events, got %d: %+v", len(ev), ev)
	}
	want := []string{"login_success", "login_failure", "sudo", "su_session", "user_added"}
	for i, k := range want {
		if ev[i].Kind != k {
			t.Errorf("event %d: want %s got %s", i, k, ev[i].Kind)
		}
	}
	if ev[0].Attrs["ip"] != "198.51.100.20" || ev[1].Attrs["user"] != "admin" || ev[2].Attrs["as"] != "root" {
		t.Errorf("attrs wrong: %+v %+v %+v", ev[0].Attrs, ev[1].Attrs, ev[2].Attrs)
	}
	if ev[3].Attrs["user"] != "kodeblue" || ev[3].Attrs["by"] != "root" {
		t.Errorf("su parse wrong: %+v", ev[3].Attrs)
	}
	if ev[4].Attrs["uid"] != "0" {
		t.Errorf("useradd uid: %+v", ev[4].Attrs)
	}
}

// kinds lists the events as "kind user@ip" (or "kind subject").
func kinds(ev []Event) []string {
	var out []string
	for _, e := range ev {
		s := e.Kind + " " + e.Subject
		if ip, ok := e.Attrs["ip"]; ok {
			s = e.Kind + " " + e.Attrs["user"] + "@" + ip
		}
		out = append(out, s)
	}
	return out
}

func wantKinds(t *testing.T, name string, ev []Event, want ...string) {
	t.Helper()
	if got := kinds(ev); !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

// Lines as each distribution writes them, captured from real sshd, sudo,
// su and shadow-utils in containers: rsyslog files (Ubuntu and Debian with
// RFC 3339 timestamps, RHEL's /var/log/secure with traditional ones) and
// journalctl -o short-iso, which kodeblue reads where there is no file.
// OpenSSH 9.8+ (Debian 13, Fedora, Rocky 9.7) logs as sshd-session.
func TestParseAuthDistros(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  []string
	}{
		{"ubuntu 24.04 auth.log (OpenSSH 9.6p1)", []string{
			"2026-10-24T11:19:33.475869+00:00 c2719c311cff useradd[3859]: new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/sh, from=none",
			"2026-10-24T11:19:33.656884+00:00 c2719c311cff chpasswd[3868]: pam_unix(chpasswd:chauthtok): password changed for bob",
			"2026-10-24T11:19:34.007958+00:00 c2719c311cff sshd[3874]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root",
			"2026-10-24T11:19:36.296581+00:00 c2719c311cff sshd[3874]: Failed password for root from 127.0.0.1 port 38848 ssh2",
			"2026-10-24T11:19:44.607687+00:00 c2719c311cff sshd[3874]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 38848 ssh2]",
			"2026-10-24T11:19:46.697044+00:00 c2719c311cff sshd[3874]: Connection closed by authenticating user root 127.0.0.1 port 38848 [preauth]",
			"2026-10-24T11:19:47.627830+00:00 c2719c311cff sshd[3881]: Invalid user admin from 127.0.0.1 port 44262",
			"2026-10-24T11:19:49.812736+00:00 c2719c311cff sshd[3881]: Failed password for invalid user admin from 127.0.0.1 port 44262 ssh2",
			"2026-10-24T11:19:52.521786+00:00 c2719c311cff sshd[3881]: Failed password for invalid user admin from 127.0.0.1 port 44262 ssh2",
			"2026-10-24T11:19:53.037149+00:00 c2719c311cff sshd[3881]: Connection closed by invalid user admin 127.0.0.1 port 44262 [preauth]",
			"2026-10-24T11:20:00.854574+00:00 c2719c311cff sshd[3892]: Accepted password for bob from 127.0.0.1 port 42152 ssh2",
			"2026-10-24T11:20:00.916933+00:00 c2719c311cff sshd[3892]: pam_unix(sshd:session): session opened for user bob(uid=1001) by bob(uid=0)",
			"2026-10-24T11:20:01.089474+00:00 c2719c311cff sshd[3904]: Received disconnect from 127.0.0.1 port 42152:11: disconnected by user",
			"2026-10-24T11:20:01.293831+00:00 c2719c311cff sshd[3909]: banner exchange: Connection from 127.0.0.1 port 42156: invalid format",
			"2026-10-24T11:20:02.301453+00:00 c2719c311cff usermod[3916]: add 'bob' to group 'ops'",
			"2026-10-24T11:20:02.406115+00:00 c2719c311cff su[3923]: pam_unix(su:session): session opened for user bob(uid=1001) by (uid=0)",
			"2026-10-24T11:20:02.513766+00:00 c2719c311cff sudo:      bob : PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
			"2026-10-24T11:20:02.515934+00:00 c2719c311cff sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1001)",
			"2026-10-24T11:20:02.540527+00:00 c2719c311cff su[3927]: pam_unix(su-l:session): session opened for user bob(uid=1001) by (uid=0)",
		}, []string{
			"user_added bob", "password_changed bob",
			"login_failure root@127.0.0.1", "login_failure root@127.0.0.1", "login_failure root@127.0.0.1",
			"login_invalid_user admin@127.0.0.1", "login_failure admin@127.0.0.1",
			"login_success bob@127.0.0.1",
			"group_added bob", "su_session bob", "sudo bob", "su_session bob",
		}},
		{"debian 13 auth.log (OpenSSH 10.0p2)", []string{
			"2026-10-24T11:19:04.093862+00:00 03bbc3e17545 sshd-session[1073]: Failed password for root from 127.0.0.1 port 58636 ssh2",
			"2026-10-24T11:19:06.332094+00:00 03bbc3e17545 sshd-session[1073]: Failed password for root from 127.0.0.1 port 58636 ssh2",
			"2026-10-24T11:19:08.886236+00:00 03bbc3e17545 sshd-session[1073]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root",
			"2026-10-24T11:19:09.011114+00:00 03bbc3e17545 sshd-session[1083]: Invalid user admin from 127.0.0.1 port 35654",
			"2026-10-24T11:19:10.988132+00:00 03bbc3e17545 sshd-session[1083]: Failed password for invalid user admin from 127.0.0.1 port 35654 ssh2",
			"2026-10-24T11:19:14.495327+00:00 03bbc3e17545 sshd-session[1083]: Failed password for invalid user admin from 127.0.0.1 port 35654 ssh2",
			"2026-10-24T11:19:20.575874+00:00 03bbc3e17545 sshd-session[1095]: Accepted password for bob from 127.0.0.1 port 51862 ssh2",
			"2026-10-24T11:19:21.948098+00:00 03bbc3e17545 usermod[1114]: add 'bob' to group 'ops'",
			"2026-10-24T11:19:21.950739+00:00 03bbc3e17545 usermod[1114]: add 'bob' to shadow group 'ops'",
		}, []string{
			"login_failure root@127.0.0.1", "login_failure root@127.0.0.1",
			"login_invalid_user admin@127.0.0.1", "login_failure admin@127.0.0.1",
			"login_success bob@127.0.0.1", "group_added bob", "group_added bob",
		}},
		{"fedora 43 rsyslog (OpenSSH 10.2p1)", []string{
			"Oct 24 11:19:04 4b99231951b1 sshd-session[137]: Failed password for root from 127.0.0.1 port 58622 ssh2",
			"Oct 24 11:19:12 4b99231951b1 sshd-session[147]: Invalid user admin from 127.0.0.1 port 35656",
			"Oct 24 11:19:14 4b99231951b1 sshd-session[147]: Failed password for invalid user admin from 127.0.0.1 port 35656 ssh2",
			"Oct 24 11:19:23 4b99231951b1 sshd-session[159]: Accepted password for bob from 127.0.0.1 port 51870 ssh2",
			"Oct 24 11:19:25 4b99231951b1 sudo:      bob : PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
		}, []string{"login_failure root@127.0.0.1", "login_invalid_user admin@127.0.0.1", "login_success bob@127.0.0.1", "sudo bob"}},
		{"rocky 9 /var/log/secure (OpenSSH 9.9p1)", []string{
			"Oct 24 11:19:27 ac31c8b54ac6 useradd[238]: new user: name=bob, UID=1000, GID=1000, home=/home/bob, shell=/bin/bash, from=none",
			"Oct 24 11:19:30 ac31c8b54ac6 sshd-session[255]: Failed password for root from 127.0.0.1 port 38834 ssh2",
			"Oct 24 11:19:35 ac31c8b54ac6 sshd-session[255]: message repeated 2 times: [ Failed password for root from 127.0.0.1 port 38834 ssh2]",
			"Oct 24 11:19:36 ac31c8b54ac6 sshd-session[262]: Invalid user admin from 127.0.0.1 port 51418",
			"Oct 24 11:19:39 ac31c8b54ac6 sshd-session[262]: Failed password for invalid user admin from 127.0.0.1 port 51418 ssh2",
			"Oct 24 11:19:42 ac31c8b54ac6 sshd-session[262]: Failed password for invalid user admin from 127.0.0.1 port 51418 ssh2",
			"Oct 24 11:19:48 ac31c8b54ac6 sshd-session[273]: Accepted password for bob from 127.0.0.1 port 44270 ssh2",
			"Oct 24 11:19:51 ac31c8b54ac6 su: pam_unix(su:session): session opened for user bob(uid=1000) by (uid=0)",
			"Oct 24 11:19:51 ac31c8b54ac6 sudo:      bob : PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
			"Oct  4 11:19:51 ac31c8b54ac6 su: pam_unix(su-l:session): session opened for user bob(uid=1000) by root(uid=0)",
		}, []string{
			"user_added bob",
			"login_failure root@127.0.0.1", "login_failure root@127.0.0.1", "login_failure root@127.0.0.1",
			"login_invalid_user admin@127.0.0.1", "login_failure admin@127.0.0.1",
			"login_success bob@127.0.0.1", "su_session bob", "sudo bob", "su_session bob",
		}},
		{"debian 13 journal (OpenSSH 10.0p2)", []string{
			"2026-10-24T11:26:45+00:00 66ccfbce257f sshd[960]: Server listening on 0.0.0.0 port 22.",
			"2026-10-24T11:26:48+00:00 66ccfbce257f sshd-session[976]: Failed password for root from 127.0.0.1 port 40890 ssh2",
			"2026-10-24T11:26:51+00:00 66ccfbce257f sshd-session[984]: Invalid user admin from 127.0.0.1 port 60556",
			"2026-10-24T11:26:51+00:00 66ccfbce257f sshd-session[984]: pam_unix(sshd:auth): check pass; user unknown",
			"2026-10-24T11:26:53+00:00 66ccfbce257f sshd-session[984]: Failed password for invalid user admin from 127.0.0.1 port 60556 ssh2",
			"2026-10-24T11:26:54+00:00 66ccfbce257f sshd-session[989]: Accepted password for bob from 127.0.0.1 port 60560 ssh2",
			"2026-10-24T11:26:54+00:00 66ccfbce257f su[1000]: pam_unix(su:session): session opened for user bob(uid=1000) by (uid=0)",
			"2026-10-24T11:26:54+00:00 66ccfbce257f sudo[1003]:      bob : PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
		}, []string{"login_failure root@127.0.0.1", "login_invalid_user admin@127.0.0.1", "login_success bob@127.0.0.1", "su_session bob", "sudo bob"}},
		{"fedora 43 journal (OpenSSH 10.2p1)", []string{
			"2026-10-24T11:27:06+00:00 2065dd81bd7d useradd[118]: new user: name=bob, UID=1000, GID=1000, home=/home/bob, shell=/bin/bash, from=none",
			"2026-10-24T11:27:08+00:00 2065dd81bd7d sshd-session[124]: Failed password for root from 127.0.0.1 port 43164 ssh2",
			"2026-10-24T11:27:16+00:00 2065dd81bd7d sshd-session[137]: Accepted password for bob from 127.0.0.1 port 53708 ssh2",
			"2026-10-24T11:27:17+00:00 2065dd81bd7d sudo[156]:      bob : PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
		}, []string{"user_added bob", "login_failure root@127.0.0.1", "login_success bob@127.0.0.1", "sudo bob"}},
		{"older journalctl short-iso offset", []string{
			"2026-10-24T11:27:08+0000 web sshd[124]: Failed password for root from 203.0.113.7 port 43164 ssh2",
		}, []string{"login_failure root@203.0.113.7"}},
		{"sshd-auth (OpenSSH 10 pre-auth binary), IPv6 and publickey", []string{
			"Oct 24 12:21:30 rhel10 sshd-auth[1402]: Failed password for root from 2001:db8::7 port 44120 ssh2",
			"Oct 24 12:21:31 rhel10 sshd-session[1403]: Accepted publickey for bob from 198.51.100.4 port 51040 ssh2: ED25519 SHA256:Zp1NnYHdBPk3WEYcGmT/4D2Uxl2rD0nqK2PdWmYzrq0",
			"Oct 24 12:21:32 rhel10 sshd-session[1404]: Failed publickey for invalid user git from 203.0.113.4 port 51041 ssh2: RSA SHA256:Zp1NnYHdBPk3WEYcGmT/4D2Uxl2rD0nqK2PdWmYzrq0",
			"Oct 24 12:21:33 rhel10 sshd-session[1405]: Failed publickey for deploy from 203.0.113.4 port 51042 ssh2: ED25519-CERT SHA256:Zp1NnYHdBPk3WEYcGmT/4D2Uxl2rD0nqK2PdWmYzrq0 ID deploy key for ci (serial 7) CA ED25519 SHA256:3Fq9cLkUPFg0bTzNvC8mE1a2b3c4d5e6f7g8h9i0jkl",
			"Oct 24 12:21:34 rhel10 sshd-session[1406]: Failed publickey for root from 203.0.113.4 port 51043 ssh2: RSA MD5:1f:2e:3d:4c:5b:6a:79:88:97:a6:b5:c4:d3:e2:f1:00",
			"Oct 24 12:21:35 rhel10 sshd-session[1407]: Failed hostbased for root from 203.0.113.4 port 51044 ssh2: ECDSA SHA256:Zp1NnYHdBPk3WEYcGmT/4D2Uxl2rD0nqK2PdWmYzrq0, client user \"root\", client host \"x\"",
		}, []string{"login_failure root@2001:db8::7", "login_success bob@198.51.100.4", "login_failure git@203.0.113.4", "login_failure deploy@203.0.113.4", "login_failure root@203.0.113.4", "login_failure root@203.0.113.4"}},
	}
	for _, c := range cases {
		wantKinds(t, c.name, parseAuthLines(c.lines), c.want...)
	}
}

// A remote client controls its user name (sshd cuts it at a ':'), its key
// exchange offer and its disconnect reason, and all of them reach the log. None
// may turn into a login, or move a failure to another address.
func TestParseAuthForgery(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		// Real sshd 9.6p1, sent an unauthenticated KEXINIT: on main this
		// was a login_success for root@198.51.100.66.
		{"key exchange offer", `2026-10-24T11:24:57.161979+00:00 a0b0e3102e82 sshd[71]: Unable to negotiate with 127.0.0.1 port 60032: no matching key exchange method found. Their offer: x sshd[1]: Accepted password for root from 198.51.100.66 port 22 [preauth]`, nil},
		{"disconnect reason", `2026-10-24T12:21:26+00:00 web sshd-session[236]: Received disconnect from 203.0.113.5 port 4242:11: x sshd[1]: Accepted password for root from 1.2.3.4 port 22 [preauth]`, nil},
		// Real sshd 9.6p1, user name "a from 192.0.2.10 port 1 x": on main
		// these were two failures from 192.0.2.10.
		{"user name moving an invalid user", `2026-10-24T11:24:57.226380+00:00 a0b0e3102e82 sshd[89]: Invalid user a from 192.0.2.10 port 1 x from 172.17.0.11 port 59240`, []string{"login_invalid_user ?@172.17.0.11"}},
		{"user name moving a failure", `2026-10-24T11:24:59.396560+00:00 a0b0e3102e82 sshd[89]: Failed password for invalid user a from 192.0.2.10 port 1 x from 172.17.0.11 port 59240 ssh2`, []string{"login_failure ?@172.17.0.11"}},
		{"another program", `2026-10-24T12:21:26+00:00 web shop[77]: sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2`, nil},
		{"not at the start", `junk 2026-10-24T12:21:26+00:00 web sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2`, nil},
		{"sudo command", `2026-10-24T12:21:26+00:00 web sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/echo sshd[1]: Accepted password for root from 1.2.3.4 port 22`, []string{"sudo alice"}},
		{"user name with an escaped newline", `2026-10-24T12:21:26+00:00 web sshd[239]: Failed password for invalid user a\012b from 203.0.113.5 port 4244 ssh2`, []string{"login_failure ?@203.0.113.5"}},
		{"user name with brackets", `2026-10-24T12:21:26+00:00 web sshd[240]: Failed password for invalid user x sshd[1] from 203.0.113.5 port 4245 ssh2`, []string{"login_failure ?@203.0.113.5"}},
		{"publickey with a spaced user", `2026-10-24T12:21:26+00:00 web sshd[241]: Failed publickey for invalid user a from 192.0.2.1 port 1 ssh2 from 203.0.113.5 port 4246 ssh2: ED25519 SHA256:abc`, []string{"login_failure ?@203.0.113.5"}},
		// A certificate's key ID is the client's too.
		{"certificate key ID", `2026-10-24T12:21:26+00:00 web sshd[243]: Failed publickey for root from 203.0.113.5 port 4247 ssh2: ED25519-CERT SHA256:abc ID x from 192.0.2.1 port 1 ssh2: y (serial 0) CA ED25519 SHA256:def`, []string{"login_failure root@203.0.113.5"}},
		{"address that is not one", `2026-10-24T12:21:26+00:00 web sshd[242]: Failed password for root from 1.2.3.4;rm port 22 ssh2`, nil},
	}
	for _, c := range cases {
		ev := parseAuthLines([]string{c.line})
		wantKinds(t, c.name, ev, c.want...)
		for _, e := range ev {
			if e.Attrs["user"] == "?" && e.Attrs["user_malformed"] != "true" {
				t.Errorf("%s: malformed user not flagged: %+v", c.name, e.Attrs)
			}
		}
	}
}

func TestParseAuthRepeated(t *testing.T) {
	fail := func(port string) string {
		return "Failed password for root from 203.0.113.9 port " + port + " ssh2"
	}
	cases := []struct {
		name  string
		lines []string
		want  int
	}{
		{"folded after its line", []string{
			"Oct 24 12:21:30 web sshd[201]: " + fail("5555"),
			"Oct 24 12:21:33 web sshd[201]: message repeated 4 times: [ " + fail("5555") + "]",
		}, 5},
		{"capped", []string{
			"Oct 24 12:21:30 web sshd[202]: " + fail("5556"),
			"Oct 24 12:21:33 web sshd[202]: message repeated 999999 times: [ " + fail("5556") + "]",
		}, 1 + maxRepeat},
		{"alone", []string{
			"Oct 24 12:21:33 web sshd[203]: message repeated 5 times: [ " + fail("5557") + "]",
		}, 0},
		{"twice", []string{
			"Oct 24 12:21:30 web sshd[204]: " + fail("5558"),
			"Oct 24 12:21:33 web sshd[204]: message repeated 5 times: [ " + fail("5558") + "]",
			"Oct 24 12:21:34 web sshd[204]: message repeated 5 times: [ " + fail("5558") + "]",
		}, 6},
		{"after another line", []string{
			"Oct 24 12:21:30 web sshd[205]: " + fail("5559"),
			"Oct 24 12:21:31 web cron[9]: (root) CMD (true)",
			"Oct 24 12:21:33 web sshd[205]: message repeated 5 times: [ " + fail("5559") + "]",
		}, 1},
		{"another process's line", []string{
			"Oct 24 12:21:30 web sshd[206]: " + fail("5560"),
			"Oct 24 12:21:33 web sshd[207]: message repeated 5 times: [ " + fail("5560") + "]",
		}, 1},
		{"another message", []string{
			"Oct 24 12:21:30 web sshd[208]: " + fail("5561"),
			"Oct 24 12:21:33 web sshd[208]: message repeated 5 times: [ " + fail("5562") + "]",
		}, 1},
		{"not a login", []string{
			"Oct 24 12:21:30 web sshd[209]: Connection closed by 203.0.113.9 port 5563",
			"Oct 24 12:21:35 web sshd[209]: message repeated 2 times: [ Connection closed by 203.0.113.9 port 5563]",
		}, 0},
	}
	for _, c := range cases {
		ev := parseAuthLines(c.lines)
		if len(ev) != c.want {
			t.Errorf("%s: want %d failures, got %d", c.name, c.want, len(ev))
		}
		for _, e := range ev {
			if e.Kind != "login_failure" || e.Attrs["ip"] != "203.0.113.9" {
				t.Errorf("%s: event %+v", c.name, e)
			}
		}
	}

	// The line a count folds may be the last of the previous sweep.
	var p authParser
	ev := p.parse([]string{"Oct 24 12:21:30 web sshd[210]: " + fail("5564")})
	ev = append(ev, p.parse([]string{"Oct 24 12:21:33 web sshd[210]: message repeated 3 times: [ " + fail("5564") + "]"})...)
	if len(ev) != 4 {
		t.Errorf("across sweeps: want 4 failures, got %d", len(ev))
	}

	// However many there are, folded counts add a bounded number per sweep.
	var flood []string
	for i := range 200 {
		port := strconv.Itoa(6000 + i)
		flood = append(flood,
			"Oct 24 12:21:30 web sshd[211]: "+fail(port),
			"Oct 24 12:21:30 web sshd[211]: message repeated 20 times: [ "+fail(port)+"]")
	}
	if n := len(parseAuthLines(flood)); n != 200+maxRepeatPerParse {
		t.Errorf("per sweep: want %d failures, got %d", 200+maxRepeatPerParse, n)
	}
}

// An attempt on an account that does not exist logs "Invalid user" and then
// "Failed password for invalid user" for the same connection: one attempt.
func TestParseAuthInvalidUserOnce(t *testing.T) {
	var p authParser
	ev := p.parse([]string{
		"2026-10-24T12:21:15+00:00 web sshd[228]: Invalid user admin from 203.0.113.5 port 41890",
	})
	// The connection's failures arrive in a later sweep.
	ev = append(ev, p.parse([]string{
		"2026-10-24T12:21:17+00:00 web sshd[228]: Failed password for invalid user admin from 203.0.113.5 port 41890 ssh2",
		"2026-10-24T12:21:19+00:00 web sshd[228]: message repeated 2 times: [ Failed password for invalid user admin from 203.0.113.5 port 41890 ssh2]",
		// A probe that never tries a password still counts once.
		"2026-10-24T12:21:20+00:00 web sshd[229]: Invalid user test from 203.0.113.5 port 41891",
		"2026-10-24T12:21:20+00:00 web sshd[229]: Connection closed by invalid user test 203.0.113.5 port 41891 [preauth]",
		// Another connection's failure is not the same attempt.
		"2026-10-24T12:21:21+00:00 web sshd[230]: Failed password for invalid user admin from 203.0.113.5 port 41892 ssh2",
	})...)
	wantKinds(t, "invalid users", ev,
		"login_invalid_user admin@203.0.113.5", "login_failure admin@203.0.113.5", "login_failure admin@203.0.113.5",
		"login_invalid_user test@203.0.113.5", "login_failure admin@203.0.113.5")
}

func TestTailNewRotation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var", "log")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "auth.log")
	appendTo := func(path string, lines ...string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			_, _ = f.WriteString(l + "\n")
		}
		f.Close()
	}
	env := &Env{Root: root, State: NewCursorStore("")}
	tail := func(want ...string) {
		t.Helper()
		got, err := TailNew(env, "/var/log/auth.log")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("got %q want %q", got, want)
		}
	}

	appendTo(log, "1 history")
	tail()
	appendTo(log, "2 before rotation")
	// logrotate renames; the writer still has the old file open.
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(log+".1", "3 old file after rotation")
	appendTo(log, "4 new file")
	tail("2 before rotation", "3 old file after rotation", "4 new file")
	// Until it reopens its log, the writer keeps appending to the old one.
	appendTo(log+".1", "5 old file, late")
	appendTo(log, "6 new file")
	tail("5 old file, late", "6 new file")
	tail()

	// The next rotation compresses the oldest file and moves on.
	appendTo(log, "7 before second rotation")
	if err := os.Rename(log+".1", log+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(log+".2", "never: a file two rotations old")
	appendTo(log, "8 third file")
	tail("7 before second rotation", "8 third file")

	// Rotated and compressed before kodeblue looked: the rest is gone.
	appendTo(log, "lost")
	_ = os.Remove(log + ".1")
	if err := os.Rename(log, log+".1.gz"); err != nil {
		t.Fatal(err)
	}
	appendTo(log, "9 fourth file")
	tail("9 fourth file")

	// copytruncate: logrotate copies the file, then truncates it. What was
	// written since the last sweep is read from the copy.
	_ = os.Remove(log + ".1")
	appendTo(log, "10 before copytruncate")
	copyTruncate := func() {
		t.Helper()
		b, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(log+".1", b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(log, 0); err != nil {
			t.Fatal(err)
		}
	}
	copyTruncate()
	appendTo(log, "11 truncated")
	tail("10 before copytruncate", "11 truncated")

	// Truncated, then written past the old offset before the next sweep:
	// the file no longer starts as it did.
	appendTo(log, "12 before second copytruncate")
	copyTruncate()
	appendTo(log, "13 a line long enough to reach past where the cursor was", "14 and another")
	tail("12 before second copytruncate", "13 a line long enough to reach past where the cursor was", "14 and another")
	tail()
}

// journald gets every program name OpenSSH logs under.
func TestJournalIdents(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\n" +
		"echo '2026-10-24T12:21:30+00:00 deb13 sshd-session[312]: Failed password for root from 203.0.113.7 port 51004 ssh2'\n" +
		"echo '-- cursor: s=abc'\n"
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	env := &Env{Root: t.TempDir(), State: NewCursorStore("")}
	c := &authLogCollector{}
	_, ev, err := c.Collect(t.Context(), env)
	if err != nil {
		t.Fatal(err)
	}
	wantKinds(t, "journal", ev, "login_failure root@203.0.113.7")
	b, _ := os.ReadFile(argsFile)
	for _, id := range []string{"sshd", "sshd-session", "sshd-auth"} {
		if !strings.Contains(" "+string(b), " -t "+id+" ") {
			t.Errorf("journalctl not asked for %s: %s", id, b)
		}
	}
	if cur, _ := env.State.get("journal"); cur.Since != "s=abc" {
		t.Errorf("cursor: %+v", cur)
	}
}
