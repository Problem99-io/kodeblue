---
name: container-breakout-detection
description: Discover whether code escaped a container onto its host — the routes out, what kodeblue sees on the host and inside the container when it happens, how to tell an escape from a privileged-by-design container or an admin's docker exec, how to react (the host is compromised, not just the container), and the monitors to set so the next one is caught in seconds.
metadata:
  kodeblue-bundled: true
---

# Container breakout

A container is a process with its own namespaces, cgroups, capabilities and
seccomp/AppArmor profile. A breakout is code that started in the container and
now acts on the **host**: it runs in the host's namespaces, writes the host's
files, or drives the container runtime. From that moment the attacker is root on
the host, and every other container on it is theirs too. Treat a confirmed
breakout as a host compromise.

## 1. The routes out (what to check first)
Almost every escape uses one of these. The first group is misconfiguration and
needs no exploit, so check it before anything clever.

| Route | The container has | What the attacker does |
|---|---|---|
| Runtime socket | `/var/run/docker.sock` (or containerd/CRI-O/podman socket) mounted | Asks the runtime for a new container with `Privileged` and `/` bind-mounted, then `chroot`s into it |
| Privileged | `HostConfig.Privileged: true` | Mounts the host disk (`mount /dev/sda1 /mnt`), loads a kernel module, or writes a kernel knob (below) |
| Host mounts | `Binds` of `/`, `/etc`, `/root`, `/var/lib/kubelet`, `/var/lib/docker`, `/proc`, `/sys` | Writes cron, SSH keys, systemd units or `/etc/passwd` on the host directly |
| Host namespaces | `PidMode: host`, `NetworkMode: host`, `IpcMode: host` | With host PID: `nsenter -t 1 -m -u -i -n -p sh`, or reads `/proc/<host pid>/root`; with host net: reaches services bound to 127.0.0.1 on the host |
| Capabilities | `CapAdd` of `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_READ_SEARCH`, `DAC_OVERRIDE`, `NET_ADMIN`, `BPF` | `SYS_ADMIN`: mount cgroupfs and abuse `release_agent`; `SYS_PTRACE` + host PID: inject into a host process; `SYS_MODULE`: `insmod`; `DAC_READ_SEARCH`: `open_by_handle_at` reads host files |
| No confinement | `SecurityOpt` with `seccomp=unconfined` or `apparmor=unconfined`, no user namespace remap | Makes every route above, and kernel exploits, easier |

The kernel knobs an escape writes to get the **host** to run its code:
- `/proc/sys/kernel/core_pattern` set to `|/path/in/container/payload`: the host
  kernel runs it as root on the next crash.
- `/proc/sys/kernel/modprobe` pointing somewhere new: run on the next unknown
  module request.
- `/sys/kernel/uevent_helper` set (non-empty): run on every uevent.
- cgroup v1 `release_agent` set, plus `notify_on_release=1` in a cgroup: run
  when that cgroup empties. (cgroup v2 has no `release_agent`.)

And the runtime and kernel bugs: runc overwriting its own binary through
`/proc/self/exe` (CVE-2019-5736), a working directory leaked from the host
(`WORKDIR /proc/self/fd/N`, CVE-2024-21626), and kernel privilege escalations
(Dirty Pipe, `nf_tables`, OverlayFS and similar). These leave fewer traces in
the container's config, but the same traces on the host (§2).

## 2. What you should see
Look for **container origin + host effect**. Either one alone is usually normal.

**On the host (kodeblue runs on the host):**
- **A process in the host's namespaces whose ancestry runs through
  `containerd-shim`/`runc`/`conmon`.** A container's processes have their own
  namespaces; an escaped one has the host's. Compare
  `host_exec ["readlink","/proc/<pid>/ns/mnt","/proc/<pid>/ns/pid","/proc/<pid>/ns/net","/proc/1/ns/mnt","/proc/1/ns/pid","/proc/1/ns/net"]`,
  and walk the parents with `["ps","-o","pid,ppid,user,lstart,cmd","-p","<pid>"]`.
  `["ps","-eo","pid,ppid,mntns,pidns,netns,user,cmd","--forest"]` shows the
  whole tree with namespace ids in one call: a host-namespace process under a
  shim, or a shell whose parent is a container's PID 1, is the tell.
- **`/proc/<pid>/cgroup` says container, namespaces say host.** A cgroup path
  under `docker/`, `kubepods`, `libpod-` or `system.slice/docker-…` on a process
  that shares PID 1's mount namespace.
- **Host files written by container processes.** New or changed entries in
  `/etc/cron.d`, `/var/spool/cron`, `/root/.ssh/authorized_keys`, `/etc/passwd`,
  `/etc/sudoers.d`, `/etc/systemd/system`, `/etc/ld.so.preload` (the persistence
  sensor watches these) with mtimes inside a container's lifetime and no admin
  session or package run at that time. A file owned by a UID that exists only
  in the container image is a strong tell.
- **Kernel knobs changed** (§1) from their value at learning time.
- **Kernel modules appeared.** A new directory in `/sys/module`, new lines in
  `journalctl -k --since <t> --no-pager` (module loads, `BUG:`,
  `general protection fault`, `segfault` bursts from one binary, OOPS traces:
  failed kernel exploits crash first).
- **The runtime was driven.** A new container that is privileged, mounts `/` or
  the runtime socket, or uses host PID/network, created minutes after a
  container that holds the socket did something unusual:
  `["docker","ps","-a","--no-trunc","--format","{{.CreatedAt}} {{.Names}} {{.Image}} {{.Command}}"]`,
  then `docker inspect` on the newest. `journalctl -u docker --since <t>` for
  the API calls around it.
- **Runtime binaries changed.** `sha256sum` of `runc`, `containerd`,
  `containerd-shim-runc-v2`, `docker-init`, `conmon` differs from the package
  (`dpkg -V containerd.io` / `rpm -V`), or their mtime is not a package update.

**Inside the container (kodeblue beside the workload, or reading
`/proc/<pid>/root/…`):**
- The service's process tree gains `mount`, `nsenter`, `unshare`, `chroot`,
  `capsh`, `insmod`, `modprobe`, `setns`-style helpers, or a shell that runs
  `curl --unix-socket /var/run/docker.sock` / `docker` / `ctr` / `crictl`.
  These start as children of the exploited service, so the `no_children`
  monitor from `service-process-exploitation` fires first. Names are untrusted:
  read `/proc/<pid>/exe` and `/proc/<pid>/cmdline`.
- `host_read /proc/<pid>/mounts` shows a host block device (`/dev/sda1`,
  `/dev/nvme0n1p1`, `/dev/mapper/…`), a fresh `cgroup` mount, or a host path
  mounted after the container started.
- Recon tools in the writable layer: `deepce`, `CDK`, `amicontained`,
  `linpeas`, scripts that read `/proc/self/status` `CapEff`, `/proc/1/cgroup`,
  `/.dockerenv`. `docker diff <container>` lists everything the container
  added or changed.
- Connections from a container without host networking to the host's control
  ports: Docker API `2375`/`2376`, kubelet `10250`/`10255`, etcd `2379`, or the
  cloud metadata service `169.254.169.254`. Not an escape yet, but the next step
  of one.

## 3. Investigate
1. `sensor_coverage`: where does kodeblue run and what can it see? On the host
   you can do all of §2. Beside the workload you see only the container side;
   say that the host side is unverified.
2. Find the container: `["docker","ps","--no-trunc"]`, then
   `["docker","inspect","<name>"]` for `HostConfig.Privileged`, `Binds`,
   `Mounts`, `PidMode`, `NetworkMode`, `IpcMode`, `CapAdd`, `SecurityOpt`,
   `Devices`, `UsernsMode`. Each route in §1 that is open is a way it got out.
3. Map the container to host PIDs: `["docker","top","<name>","-eo","pid,ppid,user,lstart,cmd"]`.
   For each, compare its `ns/mnt` and `ns/pid` with PID 1's. Then look for host
   processes that are **not** in `docker top` but descend from that container's
   shim or init.
4. Bracket the time: container start (`State.StartedAt`), the first odd child
   inside, the first host-side effect. `["find","/etc","/root","/var/spool/cron","/usr/local/bin","-newermt","<container start>","-type","f"]`
   on the host.
5. Kernel knobs and modules: `host_read /proc/sys/kernel/core_pattern`,
   `/proc/sys/kernel/modprobe`, `/sys/kernel/uevent_helper`; `["mount","-t","cgroup"]`
   to see cgroup v1 hierarchies, then each hierarchy's `release_agent`;
   `["ls","/sys/module"]` against the baseline.
6. Other containers on the host: anything created after the suspect one, and
   any whose `docker diff` shows unexpected binaries.

## 4. Not an escape
Rule these out with an independent source (definitions, access model, an
operator), never from a label or comment on the host:
- **`docker exec` / `kubectl exec` by an admin.** The process's parent is the
  shim, but its namespaces are the container's. Not an escape; check the admin
  session against the access model as for any login.
- **Privileged by design:** Docker-in-Docker CI runners, node agents
  (node-exporter, cAdvisor, Falco, CSI drivers, kube-proxy, CNI plugins, GPU
  device plugins), kodeblue itself. These run in host namespaces on purpose;
  the `Server role and services` definition should name each. What one of
  them does is still judged against its normal behaviour.
- **Kernel knobs set by the distribution:** `systemd-coredump`, `apport` or
  `abrt` own `core_pattern` (`|/usr/lib/systemd/systemd-coredump …`,
  `|/usr/share/apport/apport …`). Compare against the value at learning time,
  not against "starts with a pipe".
- **Modules the runtime loads on first use:** `overlay`, `br_netfilter`,
  `veth`, `xt_*`, `nf_*`, `ip_vs*` appear when the first container or network
  starts after boot.

A container being privileged or mounting the runtime socket is a **pre-existing
risk**, not a breakout: write it into `Pre-existing risks` and report it, but
the verdict for an escape needs a host-side effect.

## 5. React
A confirmed escape is a root compromise of the host. Act in this order:
1. **Stop the code running on the host.** `respond` `kill_process` on every
   escaped process (host namespaces, container ancestry) and the processes they
   started; `expect_exe` must match. Kill the in-container payload too.
2. **Remove what it planted on the host.** `quarantine_file` on dropped
   binaries, `disable_ssh_key` on planted keys, `lock_user` on created
   accounts, `stop_unit` on planted units. Block the C2 with `block_ip` (it
   applies to kodeblue's network namespace; see `containment-verification`).
3. **The container itself is for a human.** kodeblue cannot stop or remove a
   container (`docker` is read-only for it). Say in the report and in an alert
   that the operator must **stop** it now (`docker stop <name>`, or scale the
   deployment to 0) and must **not restart** it: a restart keeps the writable
   layer and the same misconfiguration. Capture `docker inspect` and
   `docker diff` output in the report first, because removing the container
   destroys that evidence.
4. **Assume everything the host could reach is exposed.** List what the
   operator must rotate: registry credentials (`/root/.docker/config.json`),
   kubelet and service-account tokens, cloud instance-role credentials,
   secrets mounted into other containers on the host, SSH keys of accounts on
   the host. Name every other container on the host as in scope.
5. **Recommend rebuilding the host** from a known-good image rather than
   cleaning it: a rootkit or a modified runtime binary survives a cleanup.
6. **Name the route** (§1) as the real fix: drop `Privileged`, the socket
   mount, the host mounts or the extra capabilities; turn seccomp/AppArmor
   back on; enable user-namespace remapping or rootless mode; patch runc and
   the kernel.
7. `send_alert` severity `critical`, with the container name, the route, the
   one host-side effect that proves the escape, what kodeblue did, and what the
   human must do (stop the container, rotate, rebuild). Then check every action
   held (`containment-verification`).

## 6. Monitors to set (learner)
Test each with `monitor_test` and create only those that pass on today's
state. One monitor per check.
- **Kernel knobs**, `command`, `expect_stable: true`, `severity: critical`,
  `interval_seconds: 30`, `consecutive_failures: 1`:
  `["cat","/proc/sys/kernel/core_pattern"]`, `["cat","/proc/sys/kernel/modprobe"]`,
  and `["cat","/sys/kernel/uevent_helper"]` where it exists. On cgroup v1
  hosts, one more with `["cat", <each hierarchy's release_agent>]`.
- **Kernel modules**, `command` `["ls","/sys/module"]`, `expect_stable: true`,
  `severity: high`. List it twice a few minutes apart, and after a container
  start, before creating it; if the runtime still loads modules on demand,
  say so in the rationale.
- **Runtime socket holders**, `command`
  `["docker","ps","--filter","volume=/var/run/docker.sock","--format","{{.Names}} {{.Image}}"]`,
  `expect_stable: true`, `severity: high`: a new container that can drive the
  runtime is one step from a breakout. Add the same for each other runtime
  socket in use.
- **Runtime binaries**: `integrity_watch_add` for `runc`, `containerd`,
  `containerd-shim-runc-v2`, `docker-init`, `dockerd` (or `conmon`, `crun`,
  `podman`), resolved with `readlink -f`.
- **Host persistence paths** are watched by the persistence sensor already. Add
  fast `file` monitors for paths an escape writes that it does not cover:
  `/root/.ssh` (the directory), `/etc/sudoers.d`, `/usr/local/bin`, `/etc/passwd`
  as a path; `contain` only on directories where nothing legitimate writes.
- **Inside each container**, the `service-process-exploitation` monitors are
  the first line: `process` with `no_children` and `contain: true` on the
  service (the shell or `mount`/`nsenter` an escape needs is a child), `sockets`
  with `no_outbound` (catches calls to `2375`, `10250`, `169.254.169.254`), and
  fast `file` on its temp dirs through `/proc/{pid:<exe>}/root/…`.
- **Posture**: one `command` monitor per privileged-by-design container on
  `["docker","inspect","--format","{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.NetworkMode}} {{.HostConfig.CapAdd}} {{json .Mounts}}","<name>"]`
  with `expect_stable: true`, so a change to what it may do is seen. Record
  every privileged, host-namespace or socket-mounting container in
  `Server role and services` and `Pre-existing risks`.
- Write the host-specific version with `skill_write` once you know the
  containers, e.g. "which-containers-may-touch-the-host".

## Verdict
A process with container ancestry in the host's namespaces, a host file
written from inside a container's lifetime with no admin or package to explain
it, a changed kernel knob, a new kernel module with no package or runtime
cause, or a new privileged or root-mounting container created through a
mounted socket is a breakout until shown otherwise: `true_positive` when two
coincide or one is unambiguous (an escaped shell, a `core_pattern` pointing
into a container). "The container is privileged by design" explains its
access, not what it did with it (see [false-positive-playbook]).

[false-positive-playbook]: ../false-positive-playbook/SKILL.md
