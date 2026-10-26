---
name: outbound-destination-check
description: Identify who an outbound connection really goes to before calling it hostile — reverse and forward name lookups, the software's own built-in phone-home (update checks, usage stats, ACME, package mirrors), and timing against the process start and earlier sightings.
metadata:
  kodeblue-bundled: true
---

# Who is this connection to?

A service's own process connecting to a public address it was not seen using
before is either an attacker's code calling home or the software calling its
vendor. Many servers call home on their own: update checks, anonymous usage
stats, plugin catalogs, certificate renewal. These calls are rare (once a day,
or once some minutes after start), so a learning run often misses them and a
`no_outbound` monitor fires on the first one. Find out which it is before you
contain, because killing a service's main process takes the service down, and
its supervisor starts it again.

Do these checks in order. Each one costs one or two `host_exec` calls.

## 1. Name the destination
- **Reverse name:** `host_exec ["getent","hosts","<ip>"]`. A vendor or CDN name
  (`lb-140-82-121-5-fra.github.com`) says who runs the address. A cloud name
  (`ec2-35-180-167-84.eu-west-3.compute.amazonaws.com`, `*.googleusercontent.com`,
  `*.cloudfront.net`) only names the cloud provider, not its customer. Thousands
  of vendors run there, so "AWS" or "a cloud IP" is neither hostile nor an answer:
  go on to the forward check.
- **Forward match:** resolve the hostnames this software is known to contact
  (the table below, the software's own config, its documentation) with
  `host_exec ["getent","ahosts","<hostname>"]`. If the connection's exact IP is
  among the answers, you have named the service at that address. Resolve them
  now, not from memory: cloud addresses change.
- No reverse name and no forward match leaves the destination unknown. That is
  not proof of an attack, but it is not an explanation either.

## 2. Look for the setting that makes the call
Read how the process was started (`ps -o cmd -p <pid>`, `docker inspect
<container>` for the arguments, its config file) and look for the switch that
controls the call. A default that is on and not turned off is an explanation;
name it, so a human can turn it off.

| Software | Calls by default | When | Setting that controls it |
|---|---|---|---|
| Traefik | `update.traefik.io` (version check; it also reaches `api.github.com`), `collect.traefik.io` (usage stats, when enabled) | about 10 minutes after start, then every 24 hours | `--global.checknewversion=false`, `--global.sendanonymoususage=false` |
| Traefik, Caddy, certbot, any ACME client | `acme-v02.api.letsencrypt.org`, `acme.zerossl.com` | at start and before certificates expire | the ACME / TLS settings |
| Grafana | `grafana.com` (update check), `stats.grafana.org` (usage stats) | at start, then periodically | `check_for_updates`, `reporting_enabled` |
| GitLab | `version.gitlab.com` | periodically | version check and Service Ping settings |
| Coolify | `cdn.coollabs.io` (versions), its own instance (sentinel push) | periodically | auto-update settings |
| Docker daemon | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | on image pulls | registry mirrors |
| Ubuntu | `motd.ubuntu.com`, `api.snapcraft.io`, `archive.ubuntu.com`, `security.ubuntu.com`, `esm.ubuntu.com`, `ntp.ubuntu.com` | timers (`systemctl list-timers`) | `motd-news`, snapd, apt and timesyncd config |

The table holds examples, not an allow list. A match explains the destination
only when the process making the call is the one in the table, its binary is
the packaged or image one (`sha256sum`, `dpkg -S`, the image's own file
times), and the call happened when the software makes it.

## 3. Compare the timing with the process start
- Get the start time: `host_exec ["ps","-o","pid,lstart,etime,cmd","-p","<pid>"]`.
- Work out the offset of each sighting from that start. Built-in timers show
  up as a fixed offset after start (10 minutes), a fixed period (12 or 24
  hours, so a sighting at start + N days to the minute), or both.
- Earlier sightings: `findings_list` for the same monitor and earlier
  incidents with the same title. The same destinations at the same offset
  after several starts are a timer in the software. An implant does not reset
  its schedule to the process start.

## 4. Your own kill can cause the repeat
When an earlier session killed the process, the supervisor started a new one,
and the timer runs again from that start. A sighting the same few minutes after
every kill is the new process doing its normal start-up call, not the attacker
coming back. Check the offset from the latest start before you call a
repeat "re-compromise", and never kill the same service again for the same
recurring finding without new evidence (a child process, a dropped or changed
file, a destination that does not resolve to the vendor).

## Verdict
- **Explained:** the destination resolves to the software's own endpoint, the
  setting is on, the binary is the image's or package's own, and the timing
  fits. The verdict is `false_positive` (the monitor did not know about the
  call). Do not contain. In the report, name the endpoint, the setting a human
  can turn off, and the timing you saw. Record the call in the `Server role and
  services` definition with `patch_definition`. Do not add the IP to the
  monitor's `allow_remotes`: vendor addresses on shared clouds change and are
  shared with other customers; turning the call off is the fix.
- **Not explained:** no name, a name unrelated to the software, a destination
  that matches none of its endpoints, timing unrelated to the start, or other
  signs (a child process, a dropped file, a changed binary). Treat it as the
  attack explanation and contain as the responder procedure says.
- **Partly explained** (the name fits but something else does not): say what
  fits and what does not, and resolve `inconclusive` rather than killing a
  service on a guess.
