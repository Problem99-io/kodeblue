package hostexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	ok := [][]string{
		{"ss", "-tulpn"}, {"ps", "-eo", "pid,cmd"}, {"systemctl", "status", "nginx"}, {"journalctl", "-u", "ssh", "--no-pager"},
		{"find", "/tmp", "-type", "f"}, {"dpkg", "-S", "/usr/bin/ls"}, {"docker", "ps"}, {"grep", "-n", "Failed", "/var/log/auth.log"},
		{"iptables", "-S"}, {"crontab", "-l", "-u", "alice"},
	}
	for _, a := range ok {
		if err := Validate(a); err != nil {
			t.Errorf("%v should be allowed: %v", a, err)
		}
	}
	bad := [][]string{
		{"bash", "-c", "id"}, {"sh"}, {"rm", "-rf", "/"}, {"find", "/", "-exec", "rm", "{}", ";"}, {"find", "/", "-delete"},
		{"systemctl", "stop", "sshd"}, {"journalctl", "--vacuum-time=1s"}, {"docker", "run", "alpine"}, {"cat", "/etc/shadow"},
		{"grep", "-r", "x", "/etc"}, {"grep", "-rn", "x", "/etc"}, {"iptables", "-F"}, {"crontab", "-r"}, {"ip", "route", "add", "default"},
		{"tail", "-f", "/var/log/syslog"}, {"/tmp/ps"}, {"head", "/root/.ssh/id_ed25519"}, {"sort", "-o", "/etc/passwd"},
	}
	for _, a := range bad {
		if err := Validate(a); err == nil {
			t.Errorf("%v must be refused", a)
		}
	}
}

func TestSecretPaths(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/root/.ssh/id_rsa", "/home/a/.ssh/id_ed25519", "/etc/kodeblue/inference.key", "/proc/1/environ", "/etc/ssl/private/x.pem"} {
		if !IsSecretPath(p) {
			t.Errorf("%s should be secret", p)
		}
	}
	for _, p := range []string{"/etc/passwd", "/root/.ssh/authorized_keys", "/home/a/.ssh/id_ed25519.pub", "/var/log/auth.log"} {
		if IsSecretPath(p) {
			t.Errorf("%s should be readable", p)
		}
	}
}

// A file's mode and owner are not its secret: metadata commands may name a
// secret path, anything that reads content may not.
func TestMetadataOfSecretPaths(t *testing.T) {
	for _, argv := range [][]string{{"stat", "-c", "%a %U", "/etc/shadow"}, {"ls", "-l", "/etc/ssl/private/x.pem"}, {"getcap", "/root/.ssh/id_rsa"}} {
		if err := Validate(argv); err != nil {
			t.Errorf("%v: %v", argv, err)
		}
	}
	for _, argv := range [][]string{{"cat", "/etc/shadow"}, {"head", "/root/.ssh/id_rsa"}, {"strings", "/etc/ssl/private/x.pem"}, {"file", "/etc/shadow"}, {"sha256sum", "/etc/shadow"}} {
		if err := Validate(argv); err == nil {
			t.Errorf("%v reads a secret's content", argv)
		}
	}
}

// getent reads password hashes from shadow and gshadow; only the account,
// group and network databases may be queried, and -s (whose value the verb
// check would take for the database) is refused.
func TestGetentDatabases(t *testing.T) {
	ok := [][]string{{"getent", "passwd", "root"}, {"getent", "group", "sudo"}, {"getent", "hosts", "example.com"}, {"getent", "ahostsv4", "example.com"}, {"getent", "-i", "services", "ssh"}, {"getent", "initgroups", "alice"}}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
	bad := [][]string{{"getent", "shadow"}, {"getent", "shadow", "root"}, {"getent", "gshadow"}, {"getent"}, {"getent", "-s", "files", "shadow"},
		{"getent", "-s", "passwd", "shadow"}, {"getent", "-sfiles", "shadow"}, {"getent", "--service=files", "shadow"}, {"getent", "--", "shadow"}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
}

// A secret path given as a flag's value (--opt=value, an attached short-flag
// value) is still a secret path; flags with ordinary attached values keep
// working.
func TestSecretPathInFlagValues(t *testing.T) {
	bad := [][]string{
		{"wc", "--files0-from=/etc/shadow"}, {"du", "--files0-from=/etc/gshadow"}, {"grep", "-f/etc/shadow", "x", "/var/log/auth.log"},
		{"grep", "--file=/etc/shadow", "/var/log/auth.log"}, {"grep", "-nf/etc/shadow", "/var/log/auth.log"},
		{"sort", "--files0-from=/root/.ssh/id_rsa"}, {"last", "-f/etc/shadow"}, {"ausearch", "-if/etc/kodeblue/hub.key"},
	}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
	ok := [][]string{
		{"top", "-b", "-n1"}, {"tail", "-n50", "/var/log/syslog"}, {"ps", "-eo", "pid,user,etime,cmd"}, {"journalctl", "--since=-1h", "-u", "ssh"}, {"date", "--iso-8601=seconds"},
		{"grep", "-n", "-e", "Failed", "/var/log/auth.log"}, {"wc", "-l", "/etc/passwd"}, {"ss", "-tulpn"}, {"grep", "-f/home/a/.ssh/id_ed25519.pub", "/var/log/auth.log"},
	}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
}

// Commands run in workDir (/), so a relative argument that names an existing
// file there is that file; one that names nothing is a pattern or value and
// is left alone (grep environ …, grep etc/shadow in an audit log).
func TestRelativeArgs(t *testing.T) {
	defer func(d string) { workDir = d }(workDir)
	workDir = t.TempDir()
	logs := [][]string{{"grep", "environ", "/var/log/syslog"}, {"grep", "-e.key", "/var/log/syslog"}, {"grep", "etc/shadow", "/var/log/audit/audit.log"},
		{"grep", "-n", "id_rsa", "/var/log/auth.log"}, {"grep", "--file=etc/shadow", "/var/log/auth.log"}}
	for _, argv := range logs {
		if err := Validate(argv); err != nil {
			t.Errorf("%v names no file under %s, should be allowed: %v", argv, workDir, err)
		}
	}
	for _, f := range []string{"etc/shadow", "etc/gshadow", "root/.ssh/id_ed25519"} {
		p := filepath.Join(workDir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bad := [][]string{{"cat", "etc/shadow"}, {"cat", "./etc/shadow"}, {"head", "etc/../etc/gshadow"}, {"strings", "root/.ssh/id_ed25519"},
		{"grep", "--file=etc/shadow", "/var/log/auth.log"}, {"grep", "-nfetc/shadow", "/var/log/auth.log"}, {"grep", "etc/shadow", "/var/log/audit/audit.log"}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v names a secret file under %s and must be refused", argv, workDir)
		}
	}
	if err := Validate([]string{"grep", "environ", "/var/log/syslog"}); err != nil {
		t.Errorf("a pattern is not a path: %v", err)
	}
	// The real working directory: refused wherever /etc/shadow exists.
	workDir = "/"
	if _, err := os.Lstat("/etc/shadow"); err == nil {
		if err := Validate([]string{"cat", "etc/shadow"}); err == nil {
			t.Error("cat etc/shadow from / must be refused")
		}
	}
}

// ps prints other processes' environments with the BSD e modifier and the
// environ format keyword; UNIX -e (every process) and format values that
// merely contain an e stay allowed.
func TestPSEnvironment(t *testing.T) {
	bad := [][]string{{"ps", "auxe"}, {"ps", "eww"}, {"ps", "e"}, {"ps", "axe"}, {"ps", "-e", "e"}, {"ps", "-C", "sshd", "e"}, {"ps", "-p", "1", "we"},
		{"ps", "-eo", "pid,environ"}, {"ps", "-o", "environ", "-p", "1"}, {"ps", "--format=pid,environ"}, {"ps", "ax", "-O", "ENVIRON"}, {"ps", "axoenviron"},
		{"ps", "--sort", "pid", "e"}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
	ok := [][]string{{"ps", "aux"}, {"ps", "-e"}, {"ps", "-ef"}, {"ps", "-eF"}, {"ps", "-eo", "pid,user,etime,cmd"}, {"ps", "-e", "-o", "pid,etime"},
		{"ps", "axo", "pid,etime,cmd"}, {"ps", "ax", "-o", "pid,user,etime"}, {"ps", "-C", "apache2"}, {"ps", "-u", "deploy", "-o", "pid,user"},
		{"ps", "-udeploy"}, {"ps", "--sort=-etime", "-ef"}, {"ps", "--sort", "etime", "-e"}, {"ps", "-p", "1", "-o", "pid,cmd"}, {"ps", "U", "deploy"}}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
}

// systemctl show and cat print Environment= with service credentials: the
// values are redacted from the output, and --value / -P (values without
// their names) are refused.
func TestSystemctlEnvironment(t *testing.T) {
	for _, argv := range [][]string{{"systemctl", "show", "app", "-p", "Environment", "--value"}, {"systemctl", "show", "--value", "app"}, {"systemctl", "show", "-PEnvironment", "app"},
		{"systemctl", "show", "-P", "ActiveState", "app"}} {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
	for _, argv := range [][]string{{"systemctl", "show", "app"}, {"systemctl", "show", "-p", "ActiveState,Environment", "app"}, {"systemctl", "cat", "app"}} {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
	cases := []struct{ in, want string }{
		{"Environment=DB_PASSWORD=hunter2 API_KEY=sk-1\nActiveState=active", "Environment=" + redacted + "\nActiveState=active"},
		{"EnvironmentFiles=/etc/default/app (ignore_errors=no)", "EnvironmentFiles=" + redacted},
		{"Environment=\nUnsetEnvironment=FOO", "Environment=\nUnsetEnvironment=FOO"},
		{"[Service]\nEnvironment=\"TOKEN=abc\" \\\n  \"SECRET=def\"\nEnvironmentFile=-/etc/app.env\nExecStart=/usr/bin/app", "[Service]\nEnvironment=" + redacted + "\n" + redacted + "\nEnvironmentFile=" + redacted + "\nExecStart=/usr/bin/app"},
		{"  Environment = TOKEN=abc", "  Environment =" + redacted},
		// cat, head or grep of a unit file, with grep's prefixes.
		{"/etc/systemd/system/app.service:Environment=DB_URL=x", "/etc/systemd/system/app.service:Environment=" + redacted},
		{"/etc/systemd/system/app.service:7:Environment=DB_URL=x", "/etc/systemd/system/app.service:7:Environment=" + redacted},
		{"app.service-8-EnvironmentFile=/etc/default/app\n12:Environment=A=b", "app.service-8-EnvironmentFile=" + redacted + "\n12:Environment=" + redacted},
		{"PassEnvironment=HOME\nUnsetEnvironment=A=b", "PassEnvironment=HOME\nUnsetEnvironment=A=b"},
	}
	for _, c := range cases {
		if got := redactOutput(c.in); got != c.want {
			t.Errorf("redact %q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// docker/podman inspect print Config.Env: the values are redacted from the
// default JSON (names kept), and --format templates may only name fields
// away from the environment.
func TestContainerEnvironment(t *testing.T) {
	bad := [][]string{{"docker", "inspect", "--format", "{{.Config.Env}}", "web"}, {"docker", "inspect", "--format={{json .Config.Env}}", "web"},
		{"docker", "inspect", "--format", "{{json .}}", "web"}, {"docker", "inspect", "--format", "{{.Config}}", "web"}, {"docker", "inspect", "--format", "{{json .ContainerConfig}}", "img"},
		{"docker", "inspect", "--format", "{{range .Config.Env}}{{.}}{{end}}", "web"}, {"docker", "inspect", "--format", `{{index .Config "Env"}}`, "web"},
		{"docker", "inspect", "--format", "{{$c := .Config}}{{$c.Env}}", "web"}, {"docker", "inspect", "-f{{.Config.Env}}", "web"}, {"docker", "inspect", "-sf", "{{json .}}", "web"},
		{"podman", "inspect", "--format", "{{.Config.CreateCommand}}", "web"}, {"podman", "inspect", "--format", "json", "web"}, {"docker", "inspect", "--format"},
		{"docker", "logs", "-ft", "web"}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
	ok := [][]string{{"docker", "inspect", "web"}, {"podman", "inspect", "web"}, {"docker", "ps", "-a", "--no-trunc", "--format", "{{.CreatedAt}} {{.Names}} {{.Image}} {{.Command}}"},
		{"docker", "inspect", "--format", "{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.NetworkMode}} {{.HostConfig.CapAdd}} {{json .Mounts}}", "web"},
		{"docker", "ps", "--filter", "volume=/var/run/docker.sock", "--format", "{{.Names}} {{.Image}}"}, {"docker", "logs", "--tail", "50", "web"}}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
	in := `[
    {
        "Config": {
            "Hostname": "web",
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin",
                "DB_PASSWORD=hun\"ter2",
                "PASSTHROUGH"
            ],
            "Cmd": ["nginx"]
        },
        "Config2": {"Env": ["TOKEN=abc", "B=c]d"], "Image": "x"},
        "CreateCommand": [
            "podman",
            "run",
            "-e",
            "API_KEY=sk-1",
            "nginx"
        ],
        "Image": "nginx",
        "ContainerConfig": {
            "Env": [
                "SECRET=trunc`
	want := `[
    {
        "Config": {
            "Hostname": "web",
            "Env": [
                "PATH=` + redacted + `",
                "DB_PASSWORD=` + redacted + `",
                "PASSTHROUGH"
            ],
            "Cmd": ["nginx"]
        },
        "Config2": {"Env": ["TOKEN=` + redacted + `", "B=` + redacted + `"], "Image": "x"},
        "CreateCommand": [
            "podman",
            "run",
            "-e",
            "API_KEY=` + redacted + `",
            "nginx"
        ],
        "Image": "nginx",
        "ContainerConfig": {
            "Env": [
                "SECRET=` + redacted + `"`
	if got := redactOutput(in); got != want {
		t.Errorf("inspect redaction:\n got %s\nwant %s", got, want)
	}
}

// SSH host private keys end in _key, not .key; their public halves (and
// certificates) stay readable.
func TestHostKeysAreSecret(t *testing.T) {
	for _, p := range []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key", "/usr/local/etc/ssh/ssh_host_ed25519_key",
		"/proc/42/root/etc/ssh/ssh_host_ed25519_key", "/etc/dropbear/dropbear_ed25519_host_key", "/home/a/.ssh/id_ecdsa_sk", "/root/.ssh/id_dsa"} {
		if !IsSecretPath(p) {
			t.Errorf("%s should be secret", p)
		}
	}
	for _, p := range []string{"/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_rsa_key-cert.pub", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "/home/a/.ssh/known_hosts"} {
		if IsSecretPath(p) {
			t.Errorf("%s should be readable", p)
		}
	}
	if err := Validate([]string{"cat", "/etc/ssh/ssh_host_ed25519_key"}); err == nil {
		t.Error("cat of a host private key must be refused")
	}
	if err := Validate([]string{"stat", "-c", "%a %U", "/etc/ssh/ssh_host_ed25519_key"}); err != nil {
		t.Errorf("stat of a host key is metadata: %v", err)
	}
}

// host_exec resolves symlinks, as host_read does: a link (or a linked
// directory) that leads to a secret is refused for content readers, while
// metadata commands may still name it.
func TestSymlinkToSecret(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "home", ".ssh")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "id_rsa"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "notes.log")
	dirLink := filepath.Join(dir, "d")
	if err := os.Symlink(filepath.Join(keys, "id_rsa"), link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, dirLink); err != nil {
		t.Fatal(err)
	}
	bad := [][]string{{"cat", link}, {"head", "-c", "100", link}, {"cat", filepath.Join(dirLink, "id_rsa")}, {"grep", "--file=" + link, "/var/log/auth.log"},
		{"last", "-f" + link}, {"sha256sum", link}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v reads a secret through a symlink", argv)
		}
	}
	ok := [][]string{{"ls", "-l", link}, {"stat", link}, {"readlink", link}, {"realpath", link}, {"cat", filepath.Join(dir, "notes.txt")}}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
}

// App .env files and the files units load with EnvironmentFile= hold
// service credentials: both are secret paths, for host_exec and host_read.
func TestEnvFilesAreSecret(t *testing.T) {
	defer func(d []string) { unitDirs, envFilesAt = d, time.Time{} }(unitDirs)
	dir, err := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link
	if err != nil {
		t.Fatal(err)
	}
	unitDirs, envFilesAt = []string{filepath.Join(dir, "etc"), filepath.Join(dir, "lib")}, time.Time{}
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "etc", "app.service"), "[Service]\nEnvironmentFile=/etc/default/app\nExecStart=/usr/bin/app\n")
	write(filepath.Join(dir, "lib", "worker@.service"), "[Service]\n EnvironmentFile = -/srv/worker/%i.conf\n")
	write(filepath.Join(dir, "etc", "db.service.d", "override.conf"), "[Service]\nEnvironmentFile=-\"/opt/db/creds\"\n")
	write(filepath.Join(dir, "etc", "db.service.d", "notes.txt"), "EnvironmentFile=/opt/not-loaded\n")
	conf := filepath.Join(dir, "conf", "real")
	write(conf, "TOKEN=x\n")
	if err := os.Symlink(conf, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(dir, "lib", "linked.service"), "EnvironmentFile="+filepath.Join(dir, "linked")+"\n")

	for _, p := range []string{"/srv/app/.env", "/srv/app/prod.env", "/srv/app/.env.production", "/etc/default/app", "/srv/worker/eu.conf", "/opt/db/creds", filepath.Join(dir, "linked"), conf} {
		if !IsSecretPath(p) {
			t.Errorf("%s should be secret", p)
		}
	}
	for _, p := range []string{"/srv/app/.venv", "/usr/bin/printenv", "/etc/default/grub", "/srv/worker/eu/x.conf", "/opt/not-loaded", "/srv/app/env.go"} {
		if IsSecretPath(p) {
			t.Errorf("%s should be readable", p)
		}
	}
	for _, argv := range [][]string{{"cat", "/etc/default/app"}, {"grep", "PASS", "/srv/app/.env"}, {"head", "/opt/db/creds"}} {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
	if _, _, _, err := ReadFile(conf, 0, 100); err == nil {
		t.Error("host_read of an EnvironmentFile must be refused")
	}
	if err := Validate([]string{"stat", "/srv/app/.env"}); err != nil {
		t.Errorf("stat of an .env file is metadata: %v", err)
	}
}

// Values given to credential-like names are redacted wherever they appear
// (ps command lines, inspect Args and Labels, config files); log lines
// analysts need, which mention such names without a value, stay intact.
func TestCredentialRedaction(t *testing.T) {
	cases := []struct{ in, want string }{
		{"app  12  /usr/bin/app --password=hunter2 --port=80", "app  12  /usr/bin/app --password=" + redacted + " --port=80"},
		{"DB_PASSWORD=hunter2", "DB_PASSWORD=" + redacted},
		{"export MYSQL_PWD=x; GITHUB_TOKEN=ghp_1", "export MYSQL_PWD=" + redacted + "; GITHUB_TOKEN=" + redacted},
		{`"api_key": "sk 1 2", "apiKey":"x", "name": "web"`, `"api_key": "` + redacted + `", "apiKey":"` + redacted + `", "name": "web"`},
		{"api_key: sk-1\nclient_secret = abc", "api_key: " + redacted + "\nclient_secret = " + redacted},
		{"Authorization: Bearer eyJabc", "Authorization: " + redacted},
		{"GET /cb?token=abc&state=1 HTTP/1.1", "GET /cb?token=" + redacted + "&state=1 HTTP/1.1"},
		{`"Args": ["--access-key=AKIA1", "--private_key=k"]`, `"Args": ["--access-key=` + redacted + `", "--private_key=` + redacted + `"]`},
		{`"Labels": {"db.credentials": "u:p", "auth": "x"}`, `"Labels": {"db.credentials": "` + redacted + `", "auth": "` + redacted + `"}`},
		{"root 9 mysql -uroot -pS3cret appdb", "root 9 mysql -uroot -p" + redacted + " appdb"},
		{"mongosh --password x; vault login --token s.abc", "mongosh --password " + redacted + "; vault login --token " + redacted},
		{"DATABASE_URL=postgres://app:s3cret@db:5432/app", "DATABASE_URL=postgres://app:" + redacted + "@db:5432/app"},
		{`"AuthConfig": {}, "SecretOpt": [`, `"AuthConfig": {}, "SecretOpt": [`},
	}
	for _, c := range cases {
		if got := redactOutput(c.in); got != c.want {
			t.Errorf("redact %q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	intact := []string{
		"PasswordAuthentication yes",
		"/etc/ssh/sshd_config:58:PasswordAuthentication no",
		"Oct 25 10:00:01 web sshd[811]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
		"Oct 25 10:00:03 web sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2",
		"Oct 25 10:01:00 web sshd[900]: Accepted password for root from 198.51.100.4 port 40022 ssh2",
		"Oct 25 10:02:00 web sudo:      ram : TTY=pts/0 ; PWD=/home/ram ; USER=root ; COMMAND=/usr/bin/id",
		"/var/log/auth.log:12:Oct 25 10:00:03 web sshd[811]: Connection closed by authenticating user root 203.0.113.9 port 50122 [preauth]",
		"/etc/pam.d/common-auth:25:auth	[success=1 default=ignore]	pam_unix.so nullok",
		"/etc/pam.d/common-password:password requisite pam_pwquality.so retry=3",
		"/root/.ssh/authorized_keys:1:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA admin@laptop",
		`type=USER_AUTH msg=audit(1729850403.1:91): pid=811 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed'`,
		"root  1  /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --pid-file=/run/mysqld/mysqld.pid",
		"https://example.com:8443/path",
	}
	for _, l := range intact {
		if got := redactOutput(l); got != l {
			t.Errorf("must stay intact:\n got %q\nwant %q", got, l)
		}
	}
}

// Private keys and password hashes are redacted from any output, so a
// symlink swapped to a key between the check and the read still shows
// nothing secret.
func TestKeyAndHashBackstop(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACB=\n-----END OPENSSH PRIVATE KEY-----"
	cases := []struct{ in, want string }{
		{"before\n" + key + "\nafter", "before\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + redacted + "\n-----END OPENSSH PRIVATE KEY-----\nafter"},
		{"-----BEGIN ENCRYPTED PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB12\n\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END ENCRYPTED PRIVATE KEY-----",
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + redacted + "\n-----END ENCRYPTED PRIVATE KEY-----"},
		// Truncated: no END line.
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\nMIIEowIBAAKC", "-----BEGIN RSA PRIVATE KEY-----\n" + redacted},
		// Cut short, then ordinary output resumes.
		{"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5\nnext line of a log", "-----BEGIN EC PRIVATE KEY-----\n" + redacted + "\nnext line of a log"},
		// An offset read that starts inside the key.
		{"QFaA2Hwf1duRSxKtLYX5\nAwEHoUQDQgAE\n-----END EC PRIVATE KEY-----\n", redacted + "\n-----END EC PRIVATE KEY-----\n"},
		// grep's prefixes, and a key inside a JSON string.
		{"k:1:-----BEGIN PRIVATE KEY-----\nk:2:MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nk:3:-----END PRIVATE KEY-----", "k:1:-----BEGIN PRIVATE KEY-----\n" + redacted + "\nk:3:-----END PRIVATE KEY-----"},
		{`"key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n"`, `"key": "-----BEGIN PRIVATE KEY-----` + redacted + `-----END PRIVATE KEY-----\n"`},
		// Shadow and gshadow lines, also locked and behind grep's prefix.
		{"root:$y$j9T$abc$defgh:19700:0:99999:7:::\nalice:!$6$rounds=5000$salt$hash:19700::::::\nbin:*:19700:0:99999:7:::",
			"root:" + redacted + ":19700:0:99999:7:::\nalice:" + redacted + ":19700::::::\nbin:*:19700:0:99999:7:::"},
		{"/etc/shadow-:3:deploy:$2b$12$abcdefghijklmnopqrstuv:19700:0:99999:7:::", "/etc/shadow-:3:deploy:" + redacted + ":19700:0:99999:7:::"},
		{"admin:$apr1$x1$y2", "admin:" + redacted},
	}
	for _, c := range cases {
		if got := redactOutput(c.in); got != c.want {
			t.Errorf("redact %q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	for _, l := range []string{"root:x:0:0:root:/root:/bin/bash", "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ\n-----END PUBLIC KEY-----"} {
		if got := redactOutput(l); got != l {
			t.Errorf("must stay intact:\n got %q\nwant %q", got, l)
		}
	}
	// host_read of an innocent-looking file that holds a key.
	p := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(p, []byte("note\n"+key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	text, _, _, err := ReadFile(p, 0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "b3BlbnNzaC1rZXktdjE") || !strings.Contains(text, redacted) {
		t.Errorf("host_read returned the key: %q", text)
	}
}

// apt and apt-cache only read; apt-get only simulates, so an agent can see
// pending updates and write a vulnerability check on them but never install.
func TestAptReadsAndSimulates(t *testing.T) {
	ok := [][]string{{"apt", "list", "--upgradable"}, {"apt", "policy", "openssh-server"}, {"apt-cache", "policy", "sudo"},
		{"apt-get", "-s", "dist-upgrade"}, {"apt-get", "--simulate", "-q", "upgrade"}}
	for _, argv := range ok {
		if err := Validate(argv); err != nil {
			t.Errorf("%v should be allowed: %v", argv, err)
		}
	}
	bad := [][]string{{"apt-get", "upgrade"}, {"apt-get", "-q", "dist-upgrade"}, {"apt-get", "-s", "install", "nmap"}, {"apt-get", "-sy", "upgrade"},
		{"apt-get", "-s", "-o", "APT::Get::Simulate=false", "upgrade"}, {"apt", "install", "nmap"}, {"apt", "upgrade"}, {"apt-get", "-s", "update"}}
	for _, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%v must be refused", argv)
		}
	}
}
