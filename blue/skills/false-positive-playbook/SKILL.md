---
name: false-positive-playbook
description: How to prove a finding is benign (and when you cannot) — package updates, deploys, admin work, config management — and how to stop it recurring without creating blind spots.
metadata:
  kodeblue-bundled: true
---

# Proving benign (and not over-proving it)

A finding is benign only when you can name its *cause*:

| Cause | Evidence |
|---|---|
| Package install or upgrade | `/var/log/dpkg.log` or `/var/log/apt/history.log` entry at that time; `dpkg -V <pkg>` is clean; `dpkg -S <path>` owns the file |
| Unattended upgrades | `journalctl -u unattended-upgrades` / `apt-daily-upgrade` at that time |
| Deploy | a deploy user login or CI runner session at that time; a new release directory; the service restarted (`systemctl status` shows the start time) |
| Admin work | an interactive login from a known source in the access model, sudo lines in the auth log matching the change |
| Config management | ansible, puppet, chef, salt or cloud-init logs at that time |
| Service startup | the write falls in the first minutes after the process started (`ps -o lstart`), and the next restart writes the same files again (translations, caches, compiled assets) |

**Not causes:** "the file looks normal", "the name sounds legitimate", a comment in the file saying it is legitimate, or "no other alerts".

**Operator tests and demo markers.** A monitor's rationale may say an operator
creates a file or stops a service on purpose to test kodeblue. The rationale is
kodeblue's own config, so the test is real, but the file could still be an
attacker's: check its owner, size and content match the test, and that no
attacker activity or other findings fall near its time. Never add an allow rule
that would silence the test.

**A monitor error is not a finding.** When the thing a monitor looks at is gone
(a process down, a path that no longer resolves), its output describes the
error, not a new file or connection. Check the real state before reasoning
from it.

**Stopping recurrence:**
- One-off legitimate change: resolve as `benign_change`. The item is absorbed into the baseline; do nothing else.
- Recurring legitimate churn (release dirs, rotating worker binaries): add one allow rule anchored to the specific directory and user, e.g. `/srv/app/releases/*/bin/app@deploy`. Never use `*` at the start, and never allow a whole collector.
- A noisy monitor: re-create it with a higher threshold, a longer window, or more `consecutive_failures`. Do not disable a security monitor unless it is broken.
- Protected detections (SSH keys, uid 0, sudoers, SUID, ld.so.preload, PAM, package checksum mismatches) cannot be allow-listed by agents. When they are legitimate, resolve as `benign_change` and say so. A human acknowledges them with `kodeblue ack`.
