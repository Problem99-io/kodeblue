# Security policy

kodeblue watches servers and can contain attacks on them, so we take reports
about it seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:
on this repository, open **Security → Report a vulnerability**
(GitHub's private vulnerability reporting). Include:

- what is affected (agent, hub, installer, response helper) and the version
  (`kodeblue version`, `kodeblue-hub version`)
- how to reproduce it, and what an attacker gains
- any logs or proof of concept

We aim to acknowledge a report within 3 working days and to agree on a
disclosure date with you. Fixes ship as a new release; we credit reporters
who want to be credited.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope, for example:

- a way for a server's own agents, or anything they read on the host, to get
  the root response helper to act outside the root-owned policy
- a way for a hub (or a stolen hub session) to run containment, approve
  actions, or reach into a server beyond the documented message channel
- a way for one server to read or write another server's data on the hub
- enrollment, API-key, session or CSRF weaknesses in the hub
- secrets leaking into logs, transcripts, Slack or the hub

Detection gaps (an attack kodeblue does not notice) are welcome as normal
issues unless they reveal a way to blind or disable kodeblue itself.
