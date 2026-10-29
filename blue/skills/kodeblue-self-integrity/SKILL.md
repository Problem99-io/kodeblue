---
name: kodeblue-self-integrity
description: Findings about kodeblue itself — its binaries, engine, config or state changing, or kodeblue having stopped — and why they are never benign without an operator.
metadata:
  kodeblue-bundled: true
---

# kodeblue's own integrity

An attacker who controls the machine wants to blind or tamper with its
watcher. A change to kodeblue itself is therefore treated as tampering until an
operator confirms it.

## What a legitimate change looks like
- **Upgrades** through `install.sh` (a hub-driven upgrade or an operator
  re-running the installer) open a journaled 10-minute maintenance window first,
  so swapping kodeblue's binaries inside it is absorbed and does not alert.
  `stats` shows the recent journal. A finding on kodeblue's binaries usually means
  the change happened **outside** such a window: a manual copy, a build pushed by
  hand, or someone else.
- **Config** in `/etc/kodeblue` is root-owned; a change there is an operator's
  action or a root compromise.

## Check
1. `host_exec ["stat","/usr/local/bin/kodeblue"]` (and
   `/usr/local/lib/kodeblue/engine`): owner, mode, change time. Owner and mode
   must match the install (root, 0755).
2. `host_exec ["sha256sum","/usr/local/bin/kodeblue"]`: the integrity collector
   records the same SHA-256 (findings may show it shortened), so you can match the
   finding's old and new values.
3. `ps -eo pid,user,lstart,cmd`: the agent restarted shortly after the change
   and runs cleanly (`kodeblue run`, `kodeblue mcp`, the engine). Old instances may
   linger as zombies for a moment.
4. Who could have written it: logins and sudo around the change time
   (`last`, the auth log), and other files changed then
   (`find /etc /root /home /tmp /var/tmp /usr/local -newermt <time> -type f`).
5. Attack context: was an attacker active (request log, open incidents) near the
   change time? A change during an active attack keeps high severity until an
   operator confirms it.

Notes:
- The integrity baseline keeps the old hash until a finding is resolved, so a
  second change the same day reports against the original value. Line the values
  up before concluding there was only one change.
- A finding on kodeblue's binaries that is still open, waiting for an operator or
  resolved `inconclusive` keeps those paths out of maintenance absorption: until
  the operator acks it, every later upgrade alerts again. Say so when you ask for
  the ack, and check for such an older finding when an upgrade alerted.
- `kodeblue upgrade` itself runs as root from the binary its installer replaces
  (in the `kodeblue-upgrade.service` unit), which kodeblue recognises and
  journals as `absorb.upgrade` instead of reporting a deleted executable.
- A gap finding ("kodeblue was not running for …") is the same question: was it
  a planned restart or upgrade, or did something stop it?

## Verdict
Never `benign_change` on your own judgement, even when the pattern looks exactly
like an upgrade. Resolve `inconclusive`, ask on Slack whether someone deployed a
build at that time, and let the operator acknowledge it with
`kodeblue ack <finding id>`.
Without that answer, treat a change during attacker activity as a true_positive.
