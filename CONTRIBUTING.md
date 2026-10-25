# Contributing to kodeblue

Thanks for helping. Issues and pull requests are welcome; for anything larger
than a fix, please open an issue first so we can agree on the approach.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Where we need help: integrations

Right now kodeblue only learns from what it sees on the server itself. Most
teams already run security tools that see much more: a SIEM that correlates
logs across the fleet, an EDR, a cloud provider's threat detection, or a
SOAR platform with its own cases and playbooks. We want kodeblue to **pull
from those systems** and process what they report the same way it processes
its own sensors: deduplicated, triaged by the model, investigated in an
incident session, and contained under the server's policy.

Integrations we would like (one per pull request is ideal):

- **SIEM:** Wazuh, Elastic Security, Splunk, Microsoft Sentinel, Graylog,
  OpenSearch Security Analytics, Google SecOps. Pull alerts about this host,
  and let an agent run a read-only query during an investigation.
- **SOAR and case management:** TheHive, Shuffle, Tines, Cortex XSOAR,
  Splunk SOAR. Take in cases and their observables, and write kodeblue's
  verdict and incident summary back to the case.
- **Detection and threat intelligence feeds:** CrowdSec, Suricata and Zeek
  (eve.json, notice.log), Falco, osquery results, AWS GuardDuty, GCP Security
  Command Center, MISP and other STIX/TAXII feeds of indicators.
- **Alert destinations besides Slack:** syslog/CEF, generic webhooks,
  PagerDuty, Opsgenie, Microsoft Teams, email. These implement
  `notify.Sender` (`internal/blue/notify`).

Where they plug in:

- On a server, a source is a sensor: implement `sensors.Collector`
  (`internal/blue/sensors/sensors.go`) and return each external alert as an
  `Event`. Use a collector name of the source (`wazuh`, `crowdsec`), the host,
  user, IP or path it is about as `Subject`, and the source's own ID and
  severity in `Attrs`. Events then go through the same detection, dedupe and
  triage as kodeblue's own. Detection rules for the new events go in
  `internal/blue/detect`.
- For a fleet, a source that covers many servers (one SIEM for everything)
  may fit better in the hub (`internal/hub`), which can route each alert to
  the server it is about.
- Give the agents a way to look things up in the source during an
  investigation by adding a read-only MCP tool in `internal/blue/mcpserver`.

Rules for integrations, so they keep kodeblue's security model:

- **Pull, don't listen.** Servers only dial out. An integration polls the
  source's API (or reads a local file the source writes). It does not open a
  port for the source to push to.
- **Read-only access.** Document the smallest role or API scope the
  integration needs. Writing a verdict back to a case is fine; changing the
  source's rules, users or settings is not.
- **Secrets stay in config.** Tokens come from `kodeblue.toml` or a file it
  points to, with root-only permissions, never from the command line or logs.
  Redact them from errors.
- **Data from the source is untrusted input,** like any host data. Alert text
  may contain an attacker's strings: it is shown to the model as data, and it
  can never turn off a protected detection or trigger containment on its own.
- **Tested without the real service.** Add tests that run against recorded
  responses (`httptest`), including a malformed and a hostile payload.

If you want to build one, open an issue labelled `integration` first so we can
agree on where it plugs in. Issues labelled `help wanted` and
`good first issue` are good places to start.

## Build and test

You need Go (the version in `go.mod`) and, for the hub console checks, Node.js.

```bash
go build ./...
go vet ./...
go test ./...
sh deploy/build-dist.sh /tmp/dist     # release tarballs for amd64/arm64 + hub bundles
node --check internal/hub/web/app.js
```

CI (`.github/workflows/ci.yml`) runs the same steps, plus staticcheck,
govulncheck, shellcheck and the race detector.

## Branches and pull requests

- `main` is the only long-lived branch, and every release is cut from it.
  Work on a branch in your fork and open a pull request against `main`.
- One change per pull request. CI must pass and a maintainer must approve it.
- Pull requests are squash-merged (or rebased, when each commit stands on its
  own), so `main` stays linear. Write commit messages and pull request titles
  as `area: what changes`, for example `monitor: clear incidents when a
  failing condition is fixed`. Use the package or part you touched for the area.
- Rebase on `main` rather than merging it into your branch.
- Dependabot opens weekly pull requests for Go modules, GitHub Actions and the
  hub image's base images.

Maintainers: `main` and the `v*` release tags are protected by the rulesets
in `.github/rulesets/`. To apply a changed one, update it under
Settings → Rules → Rulesets, or with
`gh api -X PUT repos/Problem99-io/kodeblue/rulesets/<id> --input .github/rulesets/main.json`.

## Releases

`.github/workflows/release.yml` runs CI, then builds the release files twice
(the two builds must match byte for byte) and a multi-arch hub image.

- **Nightly** runs every night at 02:17 UTC when `main` changed since the
  last nightly. It moves the `nightly` tag, replaces the `nightly` pre-release
  and pushes `ghcr.io/problem99-io/kodeblue-hub:nightly`. Maintainers can start
  one by hand from the Actions tab ("Run workflow").
- **Stable**: tag a commit on `main` and push the tag:

  ```bash
  git tag -a v1.2.0 -m "kodeblue v1.2.0" && git push origin v1.2.0
  ```

  That publishes the `v1.2.0` release with generated notes, and the image
  as `:v1.2.0`, `:v1.2` and `:latest`. A tag with a suffix (`v1.2.0-rc.1`)
  becomes a pre-release and does not move `latest`.
- Pull requests that change the release build run all of it without publishing.

## Where things live

| Path | What |
|---|---|
| `cmd/kodeblue`, `internal/blue/` | the server agent: sensors, detection, monitors, triage, the agent runtime, MCP tools, response helper, hub link |
| `blue/` | model instructions: agent roles, triage prompt, bundled skills |
| `cmd/kodeblue-hub`, `internal/hub/` | the hub and its web console (`internal/hub/web`, plain JS under a strict CSP) |
| `cmd/kodeblue-engine`, other `internal/` packages | the agent engine kodeblue runs as a child process |
| `deploy/` | installer, release build, systemd units, example config, hub packaging |

## Guidelines

- Keep the security model intact: servers only dial out; the hub can message
  agents and approve containment only as far as each server's root-owned
  policy allows (servers can refuse hub approvals); agents get read-only,
  allowlisted tools; containment goes through the root helper.
- Detection changes need a test that shows the case they catch and, where it
  applies, the benign case they must not flag.
- Agent prompts in `blue/` are code: change them in the same pull request as
  the behaviour they describe.
- The console renders everything a server sends as text, never as HTML. Keep
  it that way.

By contributing you agree that your contributions are licensed under the
Apache License 2.0 (see [LICENSE](LICENSE)).
