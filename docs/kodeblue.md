# kodeblue

kodeblue sits on one server and is its SOC, incident response and SecOps in one. It learns what the server normally looks like, arms itself to notice changes within seconds, investigates anything suspicious in its own agent session, writes up what happened, and, if policy allows, contains the attack. Run one kodeblue per server. It runs as its own non-root `kodeblue` user that can read the whole host (see [Running as its own user](#running-as-its-own-user)).

The agents run in a small agent engine that kodeblue starts as a child process: the agent loop, tools, skills, definitions, sessions, compaction and prompt caching. kodeblue adds the layers around it (`internal/blue/…`) and the model instructions (`blue/`). See [engine.md](engine.md) for the engine itself.

## Layers

```
 fast watch  ── every 5s ── stat() of passwd/shadow/sudoers/authorized_keys/cron/systemd/pam/ld.so.preload …
     │ change ⇒ wake now
     ▼
 L1 sensors  ── every 60s ── 14 collectors read /proc, /etc, package DB, auth log          0 tokens
     ▼
 L2 detect   ── diff vs learned baseline → fixed rules → package-checksum check →          0 tokens
     │          allow rules → debounce → dedupe/cooldown
     │   + agent-authored monitors (command/file/log/http/process/port/sockets)                     0 tokens
     ▼
 route by severity:  low → digest (absorbed, reviewed daily)
                     medium/high → L3
                     critical → straight to L4
     ▼
 L3 triage   ── every 2 min, batched ── small model, one call per ≤8 findings              ~2–8k tokens
     │          benign (conf ≥ 0.85, not protected) → absorbed into baseline (+ narrow allow rule)
     │          benign but protected → operator ack (`kodeblue ack`)
     │          suspicious/malicious/unparseable → L4
     ▼
 L4 incident ── one NEW agent session per incident (blue-responder)                       bounded
     │          read-only host tools → verdict → containment via policy → report →
     │          a monitor/skill/allow rule so next time is cheaper → incident_resolve
     ▼
 L5 review   ── daily session (blue-reviewer): what's new on the server, out-of-date software,
                the day's CVEs, FP tuning, blind spots, refresh profile/definitions/skills
```

**Learning phase** (once, before detection): repeated snapshots over `learning_minutes` (so churn is learned, not alerted on), login history seeded from the auth log, then a `blue-learner` session that explores the server and writes:
- the **server profile** (`profile_set`), a ≤2000-char summary the triage model reads with every batch
- **definitions** (the engine's persistent notes), covering server role, access model, normal change patterns and pre-existing risks; every later session sees them
- **monitors**, cheap checks for what matters on this host (service health, posture, code execution, outbound connections, dropped files, attacks in the request logs)
- **coverage cases** for every service it could not cover, with what it tried and what a human could change
- **skills**, procedures specific to this server that future responders load

Then a second, short session (`blue-assessor`) records the **vulnerabilities** of each service: weaknesses someone can fix, with the evidence, how to fix each and, where one can be written, a check that tells kodeblue when it is fixed. It is a separate session so a learner that runs out of turns cannot leave the assessment out.

**Without a model** the learning phase still collects the baseline, and detection starts when it ends. The learner and the assessment wait: the hub shows **Learning is waiting for a model** on the server and the fleet page, and `kodeblue status` says so too. Once a model is set (a model connection and a default model in the hub's **Settings**, or `sudo kodeblue inference --url … --model …` with the key in `/etc/kodeblue/inference.key` and a restart), both run on their own, beside detection.

**Service coverage.** The learner does not work from what it happens to notice. `service_inventory` lists every service kodeblue finds itself, running or able to start:
- processes in system units (from their cgroup), containers (docker, podman, containerd, CRI-O), and daemons started by init;
- the owner of every listening socket, in kodeblue's network namespace and in every other one a service lives in;
- units enabled at boot or socket-activated that are not running now, and init scripts on servers without systemd.

For each service it lists the checks the service needs and what covers each one. A running service needs `health`; one that listens publicly also needs `exec` (`process` with `no_children`), `network` (`sockets`), `files` (a `file` monitor on its writable directories) and, when the request tap records its port, `requests` (log monitors). A service that is not running needs `start`, which the process sensor covers while it can see the server. OS plumbing (journald, dbus, cron and the like) needs nothing more unless it listens publicly, and `sshd`'s `exec` check is the auth sensor's job, since starting shells is what it is for.

Where no monitor can cover a check (kodeblue cannot see the process or its files, the service keeps no log, the only check would fail on normal work), the learner opens a **coverage case** with `coverage_case`. A coverage case is a case of kind `coverage` with status `needs_human`: no responder starts, since nothing is under attack. After learning and after every review, kodeblue runs the same check itself. It opens a case for every gap left without one, and resolves the cases of services whose checks monitors now cover. Coverage cases show on the hub's board and in `kodeblue status` and `kodeblue incidents`, and kodeblue posts to Slack when it opens them.

**Vulnerabilities.** For every service in the inventory the assessor looks for weaknesses someone can fix: outdated software (with the CVEs that apply to the installed version), misconfiguration, a service exposed wider than it needs, password or root login, readable secrets and loose permissions. It records each with `vulnerability_report`: the service it belongs to (`host` for the server as a whole), a severity, the evidence it observed and how to fix it. Where one can be written, a vulnerability carries a **check**: a `command`, `http` or `sockets` monitor spec that fails while the weakness exists and passes once it is fixed (`stat -c %a` on a key file expecting `600`, an admin URL expecting `403`). kodeblue refuses a check that passes when it is reported, since it would show nothing.
- Every 10 minutes kodeblue reruns the checks, without a model. An open vulnerability whose check passes is resolved; a fixed one whose check fails again is reopened, and kodeblue posts that to Slack, since a rollback or redeploy may have undone the fix.
- A vulnerability without a check stays open until an agent confirms the fix with `vulnerability_resolve`, saying how. The reviewer goes over the open ones at every review and looks at services and packages that changed.
- Accepting a risk is the team's decision: on the hub's **Vulnerabilities** tab an operator accepts a vulnerability with a reason, reopens one, or reruns its check. The server applies these without a model, and only with `hub.accept_messages`.
- `kodeblue status` lists the open vulnerabilities; the "now watching" message and the review say how many are open by severity.

**Software versions and new CVEs.** Once a day, off the main loop, kodeblue takes stock of the server's software for the reviewer:
- **Versions.** The distribution and its end of support (from `distro-info-data`), the running kernel and a pending reboot, the package updates apt already knows about with the security ones listed (`apt-get -s dist-upgrade` as the kodeblue user; the system's apt timer refreshes the lists, and lists older than 3 days are flagged), and the container images that run.
- **New CVEs.** It downloads the CVEs NIST's National Vulnerability Database published since the last pull (at most 7 days back) and the entries CISA added to its Known Exploited Vulnerabilities list, and keeps those whose affected product is a package installed here, or whose product or description names a running image or service. Products are matched by package and source package name without version, soname, `lib` or `python3-` (libc6 is glibc, libgnutls30t64 is gnutls); Linux kernel CVEs are left to the security updates. Download only: nothing about the server is sent. A failed pull is retried after an hour, doubling while it keeps failing, and the window only moves on once both feeds answered; more than 7 days behind, the gap is journaled. New matches that attackers exploit (CISA KEV) or that score 9 or more go to Slack at once, in one message, and a match CISA lists as exploited later is raised again.
- The review that follows reads both in its digest (a review due while the check runs waits for it). The reviewer confirms each CVE against the installed version before recording it with `vulnerability_report` and its CVE id. It also records an operating system past or near its end of support, pending security updates (with a check that passes once they are installed), a pending reboot, and software behind a security release. It explains in one line each CVE it ruled out.
- The feed and each source (`nvd`, `cisa_kev`) can be switched in `[cve_feed]` and, per server or fleet-wide, in the hub's Settings under *Vulnerability feed*. What the server's own config turns off the hub cannot turn on. `nvd_api_key` raises NVD's rate limit. The versions check always runs.
- The hub shows the result on each server's overview (*Software and new CVEs*): OS support, pending and security updates, a pending reboot, the feed's sources and last pull, and the latest matches.
- Agents may run `apt list`, `apt policy`, `apt-cache policy` and `apt-get -s upgrade|dist-upgrade` to check versions. `apt-get` must simulate: without `-s`, with an option value (`-s=no`), or with anything but its verb, it is refused.

To check a key file's permissions without reading it, `ls`, `stat`, `lsattr`, `getcap`, `readlink` and `realpath` may name a secret path in `host_exec` and command monitors: they read a file's mode, owner and size, never its content. Every command that reads content is still refused on a secret path.

Detections that are almost never legitimate (deleted or memfd executables, uid-0 accounts, `ld.so.preload`, SUID files in /tmp, package checksum mismatches) are still reported during learning. Otherwise a server that is already compromised would teach kodeblue that the compromise is normal.

SSH keys already in `authorized_keys` at the install's first learning sweep are learned as the admins' keys (cloud images put the provisioning key in root's), so they open no incident. Learning cannot tell those from a key an attacker planted before install, so the "now watching" message lists root's keys for a human to check and the learner records them in the access model. A key added later, while learning goes on or after it (or read first on a later sweep), is reported as usual: one in root's file is an instant critical. A relearn never learns keys this way.

**Sensor coverage.** A sensor reads one network namespace (kodeblue's) and one filesystem (`[server] root`). Anything that lives elsewhere, such as a container with its own network or root, a chroot, or a separate namespace, is invisible to it. Some sensors also have limits wherever they run: the process sensor keeps one item per program and user, so a service re-executing its own interpreter is not new; outbound only reports established TCP to public addresses; `tmp_exec` only reports files with an execute bit. kodeblue checks this itself. `sensor_coverage` (and `kodeblue sensors`) rates each sensor `ok`, `partial`, `blind` or `unavailable`, names the processes it cannot see and how to reach them (`/proc/<pid>/root`, `/proc/<pid>/net`), and says which monitors cover the gap. The learner and the reviewer build those monitors:
- `process` with `no_children`: a service that starts a program it never starts;
- `sockets`: the listeners and connections of another namespace, private destinations included;
- `file` on a directory: any new file in a workload's `/tmp`.

Monitors name processes as `{pid:<exe>}`, so they survive restarts. Once its replacements pass, an agent may turn off a **blind** sensor with `sensor_disable`, never one that still sees part of the server. Every such change is journaled and posted to Slack. The sensor turns back on by itself if a replacement monitor is disabled or the sensor can see the server again.

**Attacks on the application.** Guessed or stolen logins, API enumeration, injection and file reads through the app run inside the service: no process, file or connection changes, so no sensor sees them. Only the service's request log does. The learner finds each request log and watches it with `log` monitors:
- `path` is the log *directory* plus `file_pattern`, so the monitor follows the newest file across daily or size rotation (a first-seen file is read from its start);
- `group_by` (a regex with one capture group, normally the client address) counts the threshold per client and names the clients over it;
- attack text in the request line (traversal, SQL, template and command syntax, requests for `.env` or `.git`, scanner user agents) alerts on the first match, 4xx bursts alert per client, and `new_values: true` alerts the first time a successful login comes from a client the log has never shown.

**Request tap.** An application's own request log is not enough: many apps register their logger after some routes (static files, uploads, file browsers, admin tools) or keep no request log, and an attack confined to those routes leaves nothing to read. kodeblue therefore reads the plaintext HTTP/1.x requests reaching the listening TCP ports of its network namespace off the wire (an `AF_PACKET` socket with a kernel filter, `CAP_NET_RAW`) and writes them to `<state>/requests/access.log` in the combined log format: client address, request line, response status, user agent and `X-Forwarded-For`. Bodies, other headers and the values of secret-looking query parameters (`token`, `password`, `key`, …) are never written, and attacker text is escaped so it cannot forge log lines. kodeblue's own engine port is left out. TLS is not readable, so behind a TLS proxy the tap records the proxy's requests to the backend. `sensor_coverage` reports it as `request_tap` with its log path and ports, and the learner points the request monitors at it. `[requests] disabled = true` turns it off.

**Stopping a session.** An operator can abort a running agent session from the hub (the Stop button on a live case, or `POST /api/servers/{id}/stop-session`). It is a safety brake, allowed on any connected server regardless of `accept_learning`/`accept_messages`: the server aborts that session and resolves its case as unfinished. Detection and other sessions keep running.

**Agent reports.** An agent that finds an intrusion outside an incident (the learner reading yesterday's log, the reviewer) opens one with `finding_report`. The finding skips triage and becomes an incident at the next triage tick, so a responder contains it. Writing it into a definition or Slack alone reaches nobody who can act.

`monitor_test` backtests a log monitor's pattern on the end of the existing log (matches, counts per client, a sample) so the learner keeps patterns that are quiet on legitimate traffic. File monitors on a log directory are wrong by design: they fire on every write and teach triage that the directory always changes. A file monitor finding on a grown file now quotes the appended text (secret paths excepted), and triage judges a log finding by those lines, never by the log having grown.

**Self-triggering.** Besides the minute sweep, the fast watch stats the high-value paths every few seconds and wakes a sweep (plus immediate triage) on any change. Monitors with `fast: true` add their own paths. So a planted SSH key is an incident within seconds, not at the next tick. A gap in kodeblue's own heartbeat (it was stopped) becomes a finding on restart, and kodeblue hashes its own binaries and config.

## Keeping false positives down without going blind

| Mechanism | What it removes |
|---|---|
| **Stable identities.** Items are keyed by exe+user, proto/port/exposure/exe, key fingerprint, path. Never by PID, ephemeral port or remote CDN IP. | Restarts, worker churn, load-balanced peers |
| **Multi-snapshot learning** | Things that come and go during normal operation |
| **Package-manager verification.** dpkg md5sums and apk checksums; a changed binary that matches its package is an upgrade, not a rootkit. A config change in a package touched in the last 2h is downgraded one level, with the explanation attached. | Unattended upgrades, apt installs |
| **Severity-aware rules.** A packaged binary running for the first time is absorbed; an unpackaged one is medium; one in /tmp is high/instant. | "New process" spam |
| **Debounce.** A change must persist 2 consecutive sweeps (instant rules excepted). | Short-lived jobs, ports held during restarts |
| **Dedupe + cooldown.** One finding per fingerprint, repeats counted; no re-alert for 24h. | Alert storms |
| **Login source by /24 (/48).** A new IP inside a known prefix for that user is fine. | DHCP/ISP churn |
| **Brute force is aggregated.** One low finding per IP per day; only *success after failures* is critical. | Internet background noise |
| **Low severity never reaches a model individually.** It is recorded, absorbed, and shown in the daily digest. | Token spend on noise |
| **Triage feedback loop.** Confident benign verdicts are absorbed, and the model may propose a narrow allow rule (must match the item, ≥8 literal chars, no leading `*`, 90-day expiry). | The same benign change recurring |
| **Responder verdicts.** `false_positive` / `benign_change` absorb the items. | Investigated noise |
| **Daily reviewer.** Reads the per-rule 7-day outcome table, then tunes or disables noisy monitors, prunes stale rules, and adds monitors for blind spots. | Slow drift into noise |
| **Maintenance windows.** `kodeblue maintenance 2h` absorbs changes that are not critical during planned work, protected ones included, all journaled. | Planned admin work |

**Proactive, but not gullible.**
- **Protected detections** (new SSH keys, uid 0, sudoers, privileged groups, PAM, `ld.so.preload`, SUID, checksum mismatches, shells or netcat with outbound connections) can never be allow-listed or absorbed by a model. A benign model verdict on them asks a human (`kodeblue ack <id>`).
- Critical findings skip triage entirely.
- Triage failures escalate rather than drop.
- `inconclusive` is a first-class verdict that goes to a human.
- Every automatic decision is journaled, and the reviewer reads the journal.

## Cost

kodeblue talks to any OpenAI-compatible endpoint (`[inference] base_url`) and is designed to run a small, cheap model. The figures below assume one priced around $0.20/M input, $0.60/M output and $0.03/M cached input.

| Activity | When | Typical tokens | Typical cost |
|---|---|---|---|
| Sensors, detection, monitors | every minute | 0 | $0 |
| Triage batch | only when medium/high findings survive L2 | 2–8k in (prompt and profile mostly cached), 0.3–1k out | ≈ $0.001–0.002 |
| Incident session | per real incident | 30–150k (mostly cached system prompt + tool output) | ≈ $0.01–0.05 |
| Daily review | once a day | 30–80k | ≈ $0.01–0.03 |
| Learning | once | 100–300k | ≈ $0.03–0.08 |

The prompts are built for caching. The kodeblue system prompt, agent instructions and triage prompt are static and come first, so repeated calls mostly pay the cached-input rate. `[budget] daily_usd` caps spend: past it, only critical findings get a model, with a hard stop at 2×. Further caps: `max_incidents_per_hour` and `max_concurrent_incidents`. Spend is the cost the endpoint reports per call (`usage.cost`, or `usage.billing.billed_total_usd` on gateways that bill per request). For an endpoint that reports none, set `[budget] input_usd_per_mtok` and `output_usd_per_mtok` and kodeblue prices calls from their token counts; without either, calls count as $0, the budget is not enforced, and kodeblue logs a warning. Spend is kept in a ledger (`kodeblue status`).

## Running as its own user

| | |
|---|---|
| user | `kodeblue` (system, nologin), groups `adm`, `systemd-journal` |
| visibility | `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_AUDIT_READ` and `CAP_NET_RAW` as ambient capabilities: read any file (including `/etc/shadow` and private keys), any process, the audit log, and HTTP requests off the wire (the request tap). Non-root does not mean unprivileged: `CAP_SYS_PTRACE` also lets a process attach to any other process, so treat the `kodeblue` user as root-equivalent if it is ever compromised. Commands the agents run (`host_exec`, command monitors) inherit these capabilities, which is why they are allowlisted. |
| sandbox | `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, writable only `/var/lib/kodeblue` |
| agent host access | only via `mcp__kodeblue__*`: `host_exec` (allowlisted read-only argv commands, no shell; dangerous flags such as `find -exec`, `systemctl stop` and recursive grep are refused), `host_read`, `host_list` (names, modes, owners, sizes and times of a directory's entries, never content, so it has no secret check) and `sensor_snapshot`. Secret paths (`/etc/shadow`, private and SSH host keys, kodeblue's own config, `.env` and `*.env` files, and every file a systemd unit or drop-in loads with `EnvironmentFile=`) are refused to `host_read` and to every `host_exec` command that reads content, whether named directly, as a flag's value (`--file=…`, `-f…`), as a relative path under `/`, or through a symlink; metadata commands (`ls`, `stat`, `getcap`) may name them. `getent` never queries shadow or gshadow; `ps` refuses the BSD `e` modifier and `environ`, `systemctl` refuses `--value` and `-P`, and `docker`/`podman --format` may only reference fields away from the environment. Whatever produced it (a symlink swapped after the check included), output of `host_exec` and `host_read` is redacted, keeping the names: systemd `Environment=`/`EnvironmentFile(s)=` values (also behind grep's `file:N:` prefix), inspect `Env` arrays, values of credential-like names (`--password=`, `DB_PASSWORD=`, `"api_key":`, `Authorization:`, `--token VALUE`, mysql `-p…`, URL passwords), PEM private key bodies (also cut short) and shadow-format hashes. Lines that only name a credential, such as `Failed password for` or `PasswordAuthentication yes`, stay intact. The engine has no shell tool; its file tools are confined to kodeblue's workspace. |
| acting on the server | `respond` tool → `/run/kodeblue/respond.sock` → `kodeblue-respond@.service` (root, one process per request). Policy is re-read from the root-owned `/etc/kodeblue/kodeblue.toml`, and the helper refuses to run if that file is writable by anyone but root. On hosts without systemd, kodeblue falls back to `sudo -n kodeblue respond exec`, which needs a sudoers rule you add yourself. |

### Response actions
`kill_process` (PID-reuse check; the binary is preserved for forensics first), `quarantine_file` (non-system paths only, restorable; a restore never overwrites a file that exists at the path again; an administrator's `authorized_keys`, meaning root's, a uid 0 account's, a sudo/wheel/admin member's or a protected user's, is refused, also when named through any process's `/proc/<pid>/root`), `block_ip` (iptables/nft in kodeblue's network namespace, plus Docker's `DOCKER-USER` chain when it exists so containers are covered; loopback, link-local and protected ranges refused; a private address only when it is a mere client, never the gateway, a resolver, a peer the server dials or an SSH session), `disable_ssh_key` (refused for an administrator: root, a uid 0 account, a sudo/wheel/admin member or a protected user; the key line gets a `# kodeblue-disabled` marker; a backup of the file goes to the root-owned `/var/lib/kodeblue-respond/ssh-keys/`; undo removes only that marker, so later edits to the file survive), `lock_user` (refused for the same administrators; the account's processes are killed, and undo restores the account expiry and password lock state it had before but cannot bring the processes back), `stop_unit` (protected units refused).

The helper acts in directories other users control (home directories, `/tmp`) without following their symlinks, and refuses SSH key files that are symlinks or have more than one hard link, so a user cannot point it at another file.

Every action is journaled with its undo recipe and rate-limited (`max_actions_per_hour`). Modes:
- `off`: agents only recommend in reports
- `recommend` (default): the agent's request waits for `kodeblue respond approve <id>`
- `contain`: executes immediately

The mode in the root-owned `/etc/kodeblue/kodeblue.toml` is the ceiling. Hub operators can switch a server between modes on its Settings tab, up to that ceiling and never above it: a hub (or a stolen hub login) cannot turn on automatic containment where root did not allow it.

Undo with `kodeblue respond undo <id>`. Every action but `kill_process` can be undone: a killed process cannot be revived, so its notice says where the binary was preserved instead.

### Monitor reflexes
A payload usually runs seconds after it lands, while a model is still reading the first finding. A monitor with `contain: true` therefore acts on its own the moment it fails, with no model in the loop:
- a `process` monitor with `no_children` kills the processes the service should not have started, and everything they started;
- a `sockets` monitor with `no_outbound` kills the process holding the unexpected connection, unless it is the service itself (that is the responder's call);
- a `file` monitor quarantines new regular files in its directories (changed and removed entries are only reported).

Contain monitors run on every monitor tick (`fast_watch_seconds`). Their requests carry `requested_by: monitor:<id>` and go through the same root helper and policy as an agent's: with `off` kodeblue only journals what it would have done, with `recommend` the request waits for approval, with `contain` it runs. The finding records what was done in its `contained` evidence, so triage and the responder see it. The learner sets `contain` on the code-execution, network and dropped-file monitors of each service unless the directory legitimately gets new files.

Files in another container are reached as `/proc/<pid>/root/<path>`. The helper walks such a path inside that process's root, so a symlink in the container resolves against the container's root and cannot point the helper at the host; the inner path must still be in a quarantine-allowed location.

Findings that arrive while an incident is still being investigated join that incident, and the responder is steered onto them at once instead of a second incident opening at the next triage batch.

### Containment rules
Some attacks come back every day in the same shape: SSH password spraying from new addresses, the same exploit request against a web app from changing addresses, a dropper that keeps writing into one directory. Each time the responder asks, an operator approves, and the address is blocked. A containment rule turns that into a standing answer a person approved once.

- **Agents propose, people approve.** The reviewer (from the digest's *Recurring findings*), the responder (when an incident repeats earlier ones) or the operator agent proposes a rule with `containment_rule_propose`, naming at least two existing findings or incidents that show the pattern. A proposal does nothing. The team is asked on Slack, and the rule waits on the hub (the server's Auto-block tab) or for `sudo kodeblue rules approve <id>` on the server.
- **What a rule can do.** It answers one finding rule (`auth.bruteforce`, `monitor.<id>`, …) by taking `block_ip` on the address the finding names, or `quarantine_file` on a file under one directory (`path_prefix`, required). A `cidr` scope narrows `block_ip`. Every rule has a per-rule hourly limit (1–60) and expires after 1–90 days; it then needs approval again.
- **The approval is root's.** Approving and deleting go through the root helper, which keeps the only copy that counts in `rules.jsonl` beside the action journal (root-owned, readable by the kodeblue user). The approval names the hash of the rule the person saw, so a rule changed after it was shown is not approved. Because an approved rule acts without asking, a hub approval counts only where root let the hub turn on automatic actions: `hub.accept_approvals = true` and `[response] mode` or `hub_max_mode` is `contain`. Everywhere else rules are approved on the server. Agents can propose and pause rules, never approve or delete them.
- **When it acts.** On each sweep, before triage, the daemon runs the active rules against new findings. Each action goes to the root helper as `requested_by: rule:<id>`; the helper checks its own copy of the rule (active, unexpired, same action, target within the scope, under the rule's hourly limit) and then everything an agent's request goes through: protected addresses and paths, infrastructure, `max_actions_per_hour`. Rules act in `recommend` and `contain`, not in `off`.
- **After it acts.** The action is journaled and posted to Slack. A finding all of whose targets were contained is closed as `contained`; one a rule could not fully answer, and every critical finding, goes on to triage as usual.
- **Stopping one.** `sudo kodeblue rules pause <id> <why>` (or Pause on the hub, or an agent that sees it misfire) stops it at once; approving it again resumes it. `rules delete` removes it for good. A blocked address stays blocked: undo it with `kodeblue respond undo <id>`.

```bash
sudo kodeblue rules                  # list: waiting, active, paused, expired
sudo kodeblue rules show cr-ssh-bruteforce
sudo kodeblue rules approve cr-ssh-bruteforce        # shows the rule and asks; --yes skips the question
sudo kodeblue rules reject cr-ssh-bruteforce "our office VPN is in that range"
sudo kodeblue rules pause cr-ssh-bruteforce "blocked a partner's scanner"
```

### Guard rails on automated containment
These were added after end-to-end testing showed where a small model can over-reach:
- **`kill_process`.** The root helper only kills what looks like attacker tooling:
  - a deleted, memfd or `/tmp`-style executable
  - an unpackaged binary
  - a process holding a connection to a public IP (reverse shells, miners)
  - a process the incident's own evidence names. kodeblue computes this link itself; the model cannot assert it.

  An admin's packaged shell with no network connection is refused. In testing, a responder killed a root `tail -F` of kodeblue's log, which was the test harness.
- **`disable_ssh_key`.** Removes a planted key from a regular account. An administrator's keys (root, uid 0 accounts, sudo/wheel/admin members, `protected_users`) are never touched, because the root helper refuses, so a key planted for root is reported and recommended to a human. Keys that were part of the learned baseline can never be disabled by an agent either.
- **Protected detections are never closed on a model's word.** A `benign_change` or `false_positive` verdict on a planted key, a uid 0 account, sudoers, SUID, `ld.so.preload`, PAM or a checksum mismatch leaves the incident `needs_human` and posts a Slack "operator confirmation required". In testing, a responder found a script on the host that "explained" the planted key. It was the test harness that time, but an attacker can plant the same kind of excuse.
- **Independent evidence only.** Instructions require legitimacy to come from package records, learned definitions, a matching admin session, or an operator. Scripts, notes, comments and hostnames on the host never count.
- **Resolve nudge.** If a session ends without `incident_resolve`, kodeblue sends one follow-up in the same session before marking the incident `inconclusive`/`needs_human`.

### Prompt injection
Logs, file contents, process names and key comments are attacker-controlled. Defenses:
- Every tool result that carries host data is labelled untrusted.
- All three agent roles and the triage prompt treat instructions inside host data as an indicator of compromise.
- The tool surface is read-only except `respond`, which is policy-bound outside the model's reach.
- Monitors can only run allowlisted commands, and `http` monitors can only reach this host or private addresses, so they cannot be used to exfiltrate.
- An agent cannot blind kodeblue: whether a sensor is blind is measured by kodeblue, not stated by the model. Only a blind or unavailable sensor can be turned off, only with passing replacement monitors, and the team is told on Slack.
- No agent has web or fetch tools.

## Slack

kodeblue sends one-way updates to a Slack channel through an **incoming webhook**. It is not a bot: nothing is read back.

**With a hub, the control center owns Slack.** Configure the channel once on the hub (Settings, or `kodeblue-hub fleet set slack-webhook`). Servers never see the webhook:
- every notification goes into a durable outbox in kodeblue's database, whichever process raises it (the daemon, the agents' tool server, or the CLI)
- the hub link ships the outbox with its sync, within seconds
- the hub stores each notification once, posts it under the server's hub name, and retries with backoff when Slack is down
- the console lists every notification with its delivery status, and shows each one inside its incident's task chat

Notifications raised while the hub is unreachable wait in the outbox. A server's local webhook is ignored unless `[notify] direct = true`, which also posts straight from the server: an independent channel a compromised hub could not suppress.

**Without a hub,** put the webhook URL in `/etc/kodeblue/slack.webhook` (root:kodeblue 0640) and the server posts directly.

**Agents post themselves** with the provider-independent `send_alert` tool. It uses
the configured notification destinations (Slack, Telegram, or both), with no separate
tool per provider. Their instructions require it for:
- every `true_positive` or `inconclusive` verdict, and anything suspicious
- every containment action they executed or requested (with the undo or approve command)
- pre-existing compromise or serious risk found while learning
- reviewer escalations

They are told not to post routine benign results. The tool is capped at `agent_messages_per_hour` (default 20).

**kodeblue posts automatically**, independent of the model:
- incident opened and incident outcome (at or above `notify.min_severity`; benign outcomes are not posted)
- every containment action: executed, awaiting approval, refused, approved by an operator, or undone
- protected findings awaiting `kodeblue ack`
- "kodeblue is now watching this server" when learning completes, with how many services it found and covered, and root's authorized SSH keys to check
- coverage cases it opened for services it cannot fully monitor
- every maintenance window that opens, with its reason
- changes kodeblue made while answering a hub operator

**Safety.** Slack text can carry attacker-controlled host data relayed by a model, so every field is escaped:
- no `<links|…>`
- no `@channel` / `@here`
- URLs are de-linked

## Model instructions (`blue/`)

| File | Purpose |
|---|---|
| `internal/agent/sysprompt/base.md` | Base system prompt for every session: identity, the layer model, environment, non-negotiable rules |
| `blue/agents/blue-learner.md` | Learning procedure, deliverables, tool allowlist |
| `blue/agents/blue-assessor.md` | Vulnerability assessment after learning: per service, evidence, remediation and checks |
| `blue/agents/blue-responder.md` | Incident procedure by finding type, verdict definitions, containment rules, mandatory `incident_resolve` |
| `blue/agents/blue-reviewer.md` | Drift review + false-positive tuning procedure |
| `blue/agents/blue-operator.md` | Operator liaison: answers messages sent from the hub, within policy |
| `blue/prompts/triage.md` | Single-shot triage classifier with strict JSON output |
| `blue/skills/*` | Bundled playbooks: intrusion triage, SSH forensics, persistence hunting, miners/reverse shells, container hosts, proving-benign. Agents add server-specific skills next to them; bundled ones are refreshed on upgrade, agent-written ones are never overwritten. |

Agent definitions are registered with the engine at every start (created or patched), each with its own tool allowlist.

## What maintenance and learning never absorb

- **Maintenance windows** absorb changes that are not critical, protected ones included (a new key for a non-root user, a sudoers change), but never a critical one and never an item that a finding is still about: open, waiting for an operator, or judged an attack. The check is by path across sensors, so a dropped binary that is also a running process counts. Every window that opens is posted to Slack with its reason, because anyone with root can open one.
- **Login, sudo and su sources** are learned only when nothing was flagged. A flagged login (a new source, or success after a brute force) carries its baseline item, and is learned only after triage, an incident verdict or `kodeblue ack` judges it benign. An attacker's first login never makes its IP "known".
- **Upgrades** (`install.sh` without `--token`) open a 10-minute window that names both versions, so kodeblue swapping its own binaries is not reported as tampering. If an older integrity finding about those binaries is still waiting for an ack, the change is reported instead, by design.

## Unattended sessions

The engine is built for a human in the loop. At an agent's turn budget it pauses the run with a "Keep going?" question, and a model may ask the user something. kodeblue answers for the missing human (`internal/blue/runtime/questions.go`):
- the first checkpoint continues with an instruction to stop repeating failed calls and wrap up in at most 3 calls
- a second checkpoint ends the run
- a model's own question is told that no human is available and to decide from the evidence

kodeblue's tool server also stops loops: the third identical failing call gets a "STOP, do not send this again" note in its error. Sessions interrupted by a restart are closed at startup: incidents go to a human, and learning and review runs are marked resolved.

## Hub

Servers can report to a central console, the kodeblue hub. It shows incidents, reports, the agents' reasoning and tool calls (live), self-evaluations, monitors, findings, pending approvals and, per server, every service with its monitoring coverage and vulnerabilities, and lets operators message the agents. Servers connect out with their own API key; the hub never connects to a server and cannot change a server's policy. Setup and the security model are in [hub.md](hub.md); deployment in [deploy.md](deploy.md); locking it down in [hardening.md](hardening.md).

Agents evaluate themselves for the hub:
- the responder passes `confidence` and a `self_evaluation` to `incident_resolve` (what it verified versus assumed, what it could not check, what would have made it faster, whether the detection was well-tuned)
- the reviewer records a 1–10 score and a write-up with `self_evaluation_write`

## Operating

```bash
curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --hub https://hub.example.com --token kbe_…   # or deploy/install.sh from a release
kodeblue status                                 # heartbeat, spend, open incidents, monitors
kodeblue incidents / kodeblue incident 7        # reports
kodeblue findings --status needs_ack ; kodeblue ack 42
kodeblue maintenance 2h "deploy v42"             # planned work (reason journaled, posted to Slack)
kodeblue forget persistence|/etc/cron.d/x       # drop a wrongly learned item; next sweep re-evaluates it
kodeblue forget match 203.0.113.                # … or every baseline item containing a substring
kodeblue respond list / approve <id> / undo <id>
kodeblue rules / rules approve <id>             # containment rules the agents proposed
kodeblue vulnerabilities                        # every known vulnerability on this server
kodeblue relearn && systemctl restart kodeblue  # after a big planned change (or Relearn on the hub's Overview)
kodeblue sensors                                # what each sensor can see here, and which are off
kodeblue sensors on outbound                    # turn a sensor back on (off <sensor> <reason> turns one off)
sudo kodeblue upgrade v0.1.7                    # install that release (or Update on the hub's Overview); never automatic
```

The vulnerability register `/var/lib/kodeblue/workspace/VULNERABILITIES.md` lists everything known to be weak on the server in one place: open vulnerabilities by severity (with CVEs, evidence, fix and whether the fix's check passes), a table by service, security updates waiting, new CVEs from the daily feed that name software here, accepted risks and what was resolved in the last 30 days. kodeblue rewrites it after each sweep when something changed; `vulnerabilities.json` beside it holds the same for tools, and `sudo kodeblue vulnerabilities` prints it.

The workspace `/var/lib/kodeblue/workspace` holds everything the agents produced: `reports/` (one markdown file per incident, plus learning and review reports), `.kodeblue/skills`, and `.kodeblue/definitions`.

## Testing

- `go test ./blue/ ./internal/blue/...` covers detection and debounce, protected rules, the allowlist guard rails, response policy, and that the shipped agent and skill files parse.
- `go test ./internal/hub/` covers the hub's security properties: one-time enrollment (including concurrent reuse), hashed keys, per-server isolation of records and message replies, revocation, CSRF, sign-in throttling, gated release downloads and the console's CSP.
- `deploy/e2e/Dockerfile.bare` is a server with no kodeblue on it, for testing the real path: the hub's install command, pinned TLS, enrollment, upgrades and the hub link.
- `deploy/e2e/` contains a disposable Ubuntu "server" (sshd, cron, sudo, rsyslog, a small web app) that runs kodeblue as its own user with the same capabilities as the systemd unit. It is used for end-to-end runs; set your model endpoint in `deploy/e2e/kodeblue.toml` first.

## Cloudflare security context

Standalone servers may configure a root-owned `[cloudflare]` section with
`api_token_file = "/etc/kodeblue/cloudflare.token"` and an explicit `zone_ids`
array. Keep the token file root:kodeblue 0640; its resolved path must stay under
`/etc/kodeblue/`, which host inspection tools cannot read. An `api_token` in the
root-owned TOML is also supported. Never put the token in agent instructions.

When enrolled, configure credentials on the hub in the server's Settings tab;
local Cloudflare credentials are not used. The `cloudflare_context` tool lists
available zones when called without `ip`, and looks up recent sampled evidence
for one IP when called with `ip`, `zone_id` (optional for one configured zone),
and `hours` (1–24). See [hub configuration and limitations](hub.md#cloudflare-security-context).
