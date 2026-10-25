---
name: persistence-hunting
description: Check every common Linux persistence location when a persistence finding fires or after a confirmed compromise.
metadata:
  kodeblue-bundled: true
---

# Persistence hunting

Check these locations. For each finding, ask what it executes, whether that target is packaged (`dpkg -S` / `rpm -qf`), and when it changed relative to logins.

| Location | How to inspect |
|---|---|
| cron | `host_read /etc/crontab`, `host_list /etc/cron.d`, `host_list /var/spool/cron/crontabs`, `host_exec ["crontab","-l","-u","<user>"]` |
| systemd | `host_exec ["systemctl","list-unit-files","--state=enabled","--no-pager"]`, `host_list /etc/systemd/system`, `host_exec ["systemctl","cat","<unit>"]`; also user units in `~/.config/systemd/user` |
| timers | `host_exec ["systemctl","list-timers","--all","--no-pager"]` |
| shell init | `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.profile` — look for curl, wget, base64, nc, or `/dev/tcp` |
| loader | `/etc/ld.so.preload` (should almost never exist), `/etc/ld.so.conf.d/*` |
| PAM | `/etc/pam.d/*`: a `pam_exec.so` line or an unknown .so is a backdoor pattern; check `dpkg -V libpam-modules` |
| ssh | `~/.ssh/rc`, `/etc/ssh/sshrc`, `authorized_keys` `command=` options |
| kernel | `host_exec ["lsmod"]`, then `["modinfo","<mod>"]` for unknown modules; check `/etc/modules-load.d` |
| udev / motd | `/etc/udev/rules.d/*` with `RUN+=`, `/etc/update-motd.d/*` |
| web | new `.php`/`.jsp` files in web roots: `find <webroot> -newermt "-2 days" -name "*.php"` |

A target script in /tmp, /dev/shm or a hidden directory, or an encoded command, is an attack until proven otherwise. Containment: `quarantine_file` the dropped payload and `stop_unit` the malicious unit. Note the cron or systemd file path in the report so a human removes the entry.
