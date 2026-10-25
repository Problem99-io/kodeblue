---
name: service-restart-forensics
description: A watched service died, restarted or stopped listening — work out why, check the new process is the real one, and know when the cause cannot be found from this host.
metadata:
  kodeblue-bundled: true
---

# Service died or restarted

When monitors report a service gone ("0 running", no listener, health check
failing) and it comes back, there are three questions: why it died, whether the
new process is legitimate, and whether the death is part of an attack.

## 1. Bracket the death
- The last good sign: the last successful request in the request log, the last
  passing monitor run (`monitor_list`).
- The first bad sign: the first failing monitor run, the listener disappearing.
- Requests in that window matter most. Attack traffic just before the death is
  a likely cause (a crash exploit or an exploit that killed the process); a quiet
  log means look elsewhere.
- `response_list`: rule out kodeblue's own `kill_process` or `stop_unit`.

## 2. Check the new process
- `host_exec ["ps","-o","pid,ppid,user,lstart,etime,cmd","-p","<pid>"]`: same
  executable, same command line, same user as the baseline; no children.
- PIDs change on every restart. Compare by executable, command line and user,
  never by PID.
- A parent PID of 0 means it is supervised from outside its PID namespace (a
  container runtime). That is normal in containers.
- `readlink -f /proc/<pid>/exe` and the entrypoint's mtime (`host_list` or
  `stat` on the script or binary it runs): a newer entrypoint than the deploy
  means tampering.
- Empty drop zones as the service sees them: `/proc/<pid>/root/tmp`,
  `var/tmp`, `dev/shm`.

## 3. Expect the cold start
Many services take seconds to minutes after the process starts before they
listen. "Process up, no listener" right after a restart is a cold start until
it lasts longer than the service's normal start time (write that time into the
server-role definition). Re-check before calling it a hang.

Files written in the first minutes after a start are often the service's own
startup work (translations, caches, compiled assets). Compare file times with
the process start before calling them tampering (see
`service-process-exploitation`, §5), and remember that a restart you caused
repeats those writes.

## 4. Monitor errors are not evidence
While a process is down, monitors that look inside it fail with errors such as
"no running process" or an unresolved `{pid:…}` path. That output says the target
was missing, not that a file appeared or a connection opened. Check the real
state (`host_list`, `ss`) before you reason from it.

## 5. When the cause cannot be found here
The exit code, an out-of-memory kill and the runtime's restart reason live with
whatever supervises the service (systemd, the container runtime, the
orchestrator). kodeblue may not see them: there may be no `journalctl`,
`dmesg` or runtime CLI where it runs, and the app's stdout and stderr may go to
pipes it cannot read. Check what is available
(`host_exec ["journalctl","-u","<unit>","--since","<time>","--no-pager"]`, `free -m`);
if it is not there, say so.

## Verdict
- Death explained (deploy, admin restart, a logged crash with a known cause) and
  the new process checks out: `benign_change`.
- Cause unknown, everything else clean: `inconclusive`, never benign. Ask the
  operator for the runtime's exit records.
- Attack traffic just before the death, a changed entrypoint, or files written
  long after the start: investigate as an attack (`service-process-exploitation`,
  `web-app-attack-chain`).
