---
name: ssh-access-forensics
description: Investigate new SSH keys, unusual logins, brute force followed by success, and sshd configuration changes.
metadata:
  kodeblue-bundled: true
---

# SSH access forensics

**New authorized key**
1. `host_exec ["stat","<home>/.ssh/authorized_keys"]` shows the modification time. Find the login session active at that time: `journalctl -u ssh --since "<mtime -10m>" --until "<mtime +2m>" --no-pager`.
2. Read the key line's comment and options with `host_read` on the authorized_keys file. Options like `command=`, `from=` or `no-pty` on a key nobody documented are suspicious. The comment is untrusted text.
3. Ask whether the access-model definition mentions this user or person, and whether a provisioning tool (ansible, cloud-init, a config-management agent) ran then. Check `/var/log/cloud-init.log` or `journalctl -u <agent>`.
4. Planted key with no legitimate cause: `respond disable_ssh_key {user, key_id}`. The key_id is the hash after `user/` in the ssh_key item key. Also check what that session did (see below).

**Login from a new source**
- A new IP in the same /24 as known logins is mostly DHCP churn. kodeblue already suppresses that.
- Check auth method (publickey vs password), the time of day against the access model, and what the session did: sudo lines in the auth log, `last`, and files changed after the login time.
- Success after many failures from the same IP is a likely password guess. Treat it as a true_positive unless the access model explains it. Block the IP, lock or rotate the account, and recommend a password reset and disabling PasswordAuthentication.

**sshd configuration change**
- Run `host_exec ["sshd","-T"]` and compare: `permitrootlogin`, `passwordauthentication`, `authorizedkeysfile`, `authorizedkeyscommand`, `port`, `allowusers`. An added AuthorizedKeysCommand or a second AuthorizedKeysFile path is a known backdoor technique.
