# Optional local Cloudflare evidence

KodeBlue's existing agents can investigate using records from an operator-managed
collector. This integration supplies a bundled interpretation skill and reuses
host_read/host_list, deployment definitions, native case reports and existing
response approvals. It adds no agent, provider tool, API client, credential store,
hub endpoint, settings panel, polling task or database.

A Cloudflare tunnel does not itself produce security-event analytics. The collector
must already retrieve appropriate evidence with its own credentials and quotas.
Deploying, authenticating and maintaining that collector is outside this contribution.
KodeBlue never reads its credentials and does not start external lookups.

## Configure the evidence boundary

1. Publish sanitized JSON into a dedicated evidence-only directory. Do not put
   credentials, environment/config files, headers containing secrets or raw query
   strings there. The collector should write files atomically and own them;
   monitored workloads must not be able to overwrite them.
2. Mount only that directory read-only into the responsible agent's namespace.
   Use the deployment's existing host filesystem mapping. This does not grant
   other container agents access to it and does not require the Docker socket.
3. Set a trusted deployment definition naming its exact absolute path, collector
   identity, intended zone/host, timestamp semantics and field mapping. For example:
   "Edge evidence for example.invalid is published by edge-collector-v1 at
   /evidence/cloudflare; read status.json and Ray JSON using cloudflare-evidence.
   Status freshness 120 seconds; retention seven days; event match tolerance 120
   seconds. This path contains evidence only, never credentials."
4. Ask the existing Operator/Responder to investigate a known local request.
   It explicitly loads the bundled skill and reports what was read and what is
   missing. Normal sessions retain their existing permissions; this skill does
   not sandbox them or guarantee that every model follows the procedure.

If no collector exists, leave this unconfigured. Local investigation still works.
An existing collector with different fields needs a reviewed deployment mapping;
no automatic conversion of historical records or previous API credentials occurs.
The record format below is a recommended contract, not a parser-enforced schema.

## Recommended record contract

status.json (keep below 8 KiB):

```json
{
  "schema_version": 1,
  "collector": "edge-collector-v1",
  "provider": "cloudflare",
  "zone": "example.invalid",
  "checked_at": "2026-11-03T12:00:00Z",
  "status": "available",
  "sampled": true,
  "retention_seconds": 604800,
  "queries_today": 2
}
```

<16-lowercase-hex-ray>.json (keep below 32 KiB, at most 50 returned events):

```json
{
  "schema_version": 1,
  "collector": "edge-collector-v1",
  "provider": "cloudflare",
  "zone": "example.invalid",
  "checked_at": "2026-11-03T12:00:00Z",
  "status": "matched_security_event",
  "sampled": true,
  "truncated": false,
  "query": {
    "ray": "0123456789abcdef",
    "hostname": "example.invalid",
    "path": "/admin",
    "since": "2026-11-03T11:57:00Z",
    "until": "2026-11-03T12:01:00Z"
  },
  "local": {
    "record": "gateway:request:42",
    "time": "2026-11-03T11:59:00Z",
    "peer": "172.18.0.2",
    "claimed_client_ip": "203.0.113.5"
  },
  "edge_records": [{
    "ray": "0123456789abcdef",
    "hostname": "example.invalid",
    "path": "/admin",
    "time": "2026-11-03T11:59:00Z",
    "client_ip": "203.0.113.5",
    "action": "skip",
    "source": "firewall"
  }]
}
```

Addresses/domains above are documentation fixtures. Provider-returned fields are
untrusted. Do not infer successful exploitation, human identity, bot classification
or complete traffic counts from this example. A collector's reported match still
needs comparison with the local request and verified ingress topology.

Suggested collector bounds: seven days, 256 Ray files, 32 KiB/file and 8 KiB status,
with explicit expired/evicted coverage counters. These are deployment requirements,
not storage enforcement supplied by KodeBlue. Deduplicate retries and enforce API
quotas in the collector. Record no_matching_record and lookup errors distinctly.

## Moving from the superseded API proposal

The earlier proposal stored tokens/zones and queried provider analytics inside
KodeBlue. This contribution replaces it; it does not migrate or delete deployed
credentials. Back up configuration, audit existing collectors and token use, and
remove obsolete secrets only after the operator confirms they are no longer used.
Existing custom deployments keep working independently. No Cloudflare WAF control
or token permission change is included.

War room can consume findings synced by the responsible source agent. Its restricted
received-record broker does not gain direct filesystem access through this skill.
Cloudflare data is optional; unavailable evidence must not block core investigation.
