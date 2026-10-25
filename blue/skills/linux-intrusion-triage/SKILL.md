---
name: linux-intrusion-triage
description: First 10 minutes on a possibly compromised Linux host — what to check, in which order, with kodeblue's read-only tools.
metadata:
  kodeblue-bundled: true
---

# Linux intrusion triage (kodeblue tools only)

Work from the specific finding outward. Stop as soon as you can defend a verdict.

1. **The process tree around the finding**
   - `host_exec ["ps","-eo","pid,ppid,user,lstart,etime,cmd","--forest"]`. Look for shells under web servers (nginx, apache, php-fpm or node spawning sh or bash), and processes with odd names such as `[kworker]` that are not kernel threads (kernel threads have no exe). The same pattern counts even when the child is the *same* binary the service already runs (node re-exec'ing node, python spawning python): a service that forks at all is the event, not the child's name. A sub-second exec may already be gone from the snapshot — absence is not an all-clear (see service-process-exploitation).
   - `host_exec ["readlink","-f","/proc/<pid>/exe"]`. A `(deleted)` exe or a `memfd:` exe is a strong IOC.
   - `host_read /proc/<pid>/cmdline` and `host_list /proc/<pid>/cwd` give the working dir; attackers like /tmp, /dev/shm and /var/tmp.
2. **Network**
   - `host_exec ["ss","-tunap"]` lists established connections with their pid. Unknown outbound connections to high ports or to raw IPs on 4444/1337/9001, or IRC ports, are suspicious. Judge a service's connections against its *known egress set*, not just the port number — and an attempted or refused outbound (a connection to a closed port, visible in app logs after the socket is gone) is still an IOC.
   - `host_exec ["ss","-tulpn"]` lists listeners. Compare them with the server-role definition.
3. **Who was on the box**
   - `host_exec ["last","-n","30"]`, `["lastb","-n","30"]` and `["who"]`.
   - `host_exec ["journalctl","-u","ssh","-u","sshd","--since","-24h","--no-pager","-n","200"]`.
4. **What changed recently**
   - `host_exec ["find","/etc","/root","/home","/tmp","/var/tmp","/dev/shm","/usr/local","/opt","-xdev","-newermt","-2 hours","-type","f"]`. Adjust the time window to match the finding.
   - Check package activity in `/var/log/dpkg.log`, `/var/log/apt/history.log` or `/var/log/dnf.rpm.log` (use `host_read` with a negative offset).
5. **Integrity of the tools you rely on.** If `ps`, `ss`, `ls` or `sshd` show integrity findings, do not trust their output alone. Cross-check with `sensor_snapshot` (it reads /proc directly) and `dpkg -V`.

Verdict hints: a legitimate change has a *cause* you can point to, such as a package log line, a deploy, or an admin login that fits the access model. "Nothing else looks wrong" is not a cause.
