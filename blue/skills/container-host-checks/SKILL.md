---
name: container-host-checks
description: Investigate container-related findings on a Docker/Podman host — new containers, privileged containers, exposed ports, escapes.
metadata:
  kodeblue-bundled: true
---

# Container host checks

- New container: run `host_exec ["docker","inspect","<name>"]` and check `Image`, `Config.Cmd`, `HostConfig.Privileged`, `HostConfig.Binds` (a mount of `/`, `/etc`, `/root` or `/var/run/docker.sock` is a host-takeover risk), `HostConfig.NetworkMode` (`host`), `HostConfig.PidMode`, `CapAdd`.
- Is the image from the registry the server-role definition expects? Check `["docker","images"]` for creation time.
- Miners often run as containers: `["docker","stats","--no-stream"]` shows sustained CPU.
- A container listening publicly on a port not in the profile should be checked with `["docker","port","<name>"]`.
- Who started it: `journalctl -u docker --since <created> --no-pager`. Check who was logged in then and whether they are in the docker group (docker group membership is effectively root).
- Escape signs on the host: new files in `/etc/cron.d` or `/root/.ssh` written at container start time, or new processes on the host whose parent is `containerd-shim`. For a suspected escape, load `container-breakout-detection`: routes out, host-side traces, response and monitors.

## When kodeblue runs beside the workload (sidecar, pod, no runtime CLI)

kodeblue may share a container's process and network namespaces without seeing
its filesystem or having `docker`, `journalctl` or `dmesg`. `sensor_coverage`
says which sensors are blind there.
- Reach the workload's files as it sees them: `host_list` and `host_read` on
  `/proc/<pid>/root/…` (its `/tmp`, `/etc/passwd`, app directory). PID 1 may be
  the pod's pause process, not the app, so use the app's PID, never
  `/proc/1/root`, and in monitors write `{pid:<exe>}`.
- A parent PID of 0 means the runtime supervises the process from outside the
  namespace. That is normal, and so is a new PID after a restart.
- Restarting a container keeps its writable layer: tampered files survive it.
  Recovery from a compromise is recreating the container from its image.
- `block_ip` acts in the shared network namespace. When the pod is recreated,
  its namespace and the rule are gone (see `containment-verification`).
- What happened to the container (exit codes, OOM kills, restarts) lives with
  the runtime. When kodeblue cannot see it, say so and ask the operator (see
  `service-restart-forensics`).
