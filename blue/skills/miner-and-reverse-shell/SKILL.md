---
name: miner-and-reverse-shell
description: Recognise and contain cryptominers and reverse shells (cpu_hog, outbound.shell, outbound.suspicious_port, process.suspicious_location findings).
metadata:
  kodeblue-bundled: true
---

# Miners and reverse shells

**Miner indicators:** sustained high CPU from an unpackaged binary; names like `xmrig`, `kdevtmpfsi`, `kinsing`, or random 6–8 character strings; binaries in /tmp, /dev/shm or /var/tmp; outbound connections to 3333, 4444, 5555, 7777, 14444 or 45700; or pool hostnames. These often come with a cron or systemd re-launcher and a killer script for competing miners.

**Reverse shell indicators:** `bash -i`, `sh -i`, `nc -e`, `socat exec:`, or python/perl one-liners with socket. stdin and stdout point to a socket: `host_exec ["ls","-l","/proc/<pid>/fd"]` shows `socket:[...]` on fds 0, 1 and 2. The parent is often a web server or a service account. The child may instead be the service's own interpreter (node, python) re-exec'd rather than a named shell, and the callback may have been refused — an attempted outbound to a dead port is still the event. See service-process-exploitation.

**Investigate quickly:**
1. `ps -o pid,ppid,user,lstart,cmd -p <pid>`, then walk up the parents.
2. `readlink -f /proc/<pid>/exe` and `sha256sum` of it.
3. `ss -tunap` filtered by the pid to get remote IP and port.
4. Find the re-launcher (see persistence-hunting).

**Contain (true_positive):** kill_process (kodeblue preserves the binary for forensics first), quarantine_file for the dropped binary and its launcher script, and block_ip for the C2 or pool IP. Mention in the report how the attacker got in (the parent process, or the login session) — that is the real fix.
