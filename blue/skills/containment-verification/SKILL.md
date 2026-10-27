---
name: containment-verification
description: After any respond action — block_ip, kill_process, quarantine_file, stop_unit — check on the host that it took effect and still holds, know what each action cannot reach, and escalate when it does not hold.
metadata:
  kodeblue-bundled: true
---

# Did the containment work?

`respond` reporting `done` means the action ran, not that the attacker is cut
off. Check the effect on the host every time, and again when the situation
changes (a restart, the attacker returning).

| Action | Check that it holds |
|---|---|
| `block_ip` | `host_exec ["iptables","-L","INPUT","-n","-v"]` (or `["nft","list","ruleset"]`) shows the DROP rule; the client stops appearing in the request log after the block time; its packet counter rises if it keeps trying |
| `kill_process` | `ps` no longer shows the PID; nothing with the same executable and command line came back as a child of the same parent; any supervisor restart is the legitimate service, not the payload (see `service-restart-forensics`) |
| `quarantine_file` | `host_list` on the directory: the file is gone and not back under the same or a new name |
| `stop_unit` | `systemctl is-active <unit>` is inactive and the unit is not re-enabled by a timer or another unit |

## What each action cannot reach
- **`block_ip` works in kodeblue's network namespace.** It protects services
  that share it. A container with its own network needs a block at the host,
  network or proxy level. If the service runs in a pod whose network namespace
  is recreated (the pod restarts), the rule is gone with it.
- **`kill_process` on a supervised service** brings back a fresh process. It
  ends the attacker's running code, but not a payload stored in data, uploads or
  the container's writable layer.
- **`quarantine_file`** removes the file, not the way it got there: the attacker
  can drop it again through the same upload or exploit.
- Nothing kodeblue does removes application-level footholds (accounts, tokens,
  sessions) or the vulnerability itself.

## When it does not hold
- kodeblue re-checks an earlier block or quarantine before it treats a repeat
  request as done, and acts again when the rule or file is gone. Ask again, then
  check again.
- If it still does not hold, or the action cannot reach the attacker (other
  network namespace, outside the policy), say so plainly in the report and in
  an alert: what failed, what you saw, and the block a human must apply instead.
- Keep a tripwire: a `log` monitor for the blocked client in the request log,
  or a fast `file` monitor on the drop directory, so a return is seen in
  seconds.
