---
name: web-app-attack-chain
description: Reconstruct an attack on a web application from its request log — probing, sign-up and login, upload or admin abuse — find what the attacker achieved inside the app, and list what only a human can undo.
metadata:
  kodeblue-bundled: true
---

# Web application attack chains

Attacks on an application often never touch the host: the attacker signs up,
logs in, uploads, changes data. The request log is the evidence. Use kodeblue's
request log (`/var/lib/kodeblue/requests/access.log`, when the request tap is on)
and the application's own access log; `host_read` with a negative offset reads
the end of either.

## 1. Rebuild the chain
Filter by the client address and put the requests in order. Scripted attacks
show a steady rhythm (a request every few seconds) and a tool user agent
(`curl`, `python-requests`, `Python-urllib`, `Go-http-client`, `sqlmap`,
`nuclei`). Typical steps:
1. **Recon**: version, admin, config or API-listing endpoints, `/.git`,
   `/.env`, directory guessing (many 404s).
2. **Foothold**: account creation (`POST` to a users or register endpoint →
   201), login (→ 200 with a token or session cookie), password reset abuse.
3. **Abuse**: uploads, profile or settings changes, admin actions, order or
   payment tampering, data export, injection payloads in parameters.

## 2. Find the moment it worked
Probing fails until it does not. The status codes tell you when: a run of 4xx
or 5xx on an endpoint followed by 2xx (`410`/`500` on an upload, then `204`) is
the success. Everything after that moment is in scope. A successful upload can
write outside the upload directory: check the drop zones the service can write
(see `service-process-exploitation`).

## 3. Scope what the attacker holds inside the app
List every application-level foothold, because blocking the address does not
remove them:
- accounts created (time, from which request) and accounts logged into,
- sessions or API tokens issued, password or email changes,
- uploaded files and where they were stored,
- data changed (profiles, orders, settings) or exported.
kodeblue cannot query most application databases. Say which of these you could
confirm and which a human must check in the application.

## 4. Contain and hand over
- `block_ip` on the client as soon as the chain shows success (see
  `containment-verification` for checking it holds). A blocked attacker often
  returns from the same address after a restart, or from a new one with the same
  rhythm and user agent: a `log` monitor on the request log for that client, or
  for the first hit on sensitive endpoints, catches the return.
- The human's list, in the report: delete attacker accounts, revoke their
  sessions and tokens, remove uploads, restore changed data, and fix the
  vulnerable endpoint. Name the endpoint and the request that succeeded.

## Verdict
A client that probes and then succeeds at account creation, login, upload or an
admin action without being a known user or test client in the access model is
a true_positive, even when nothing changed on the host.
