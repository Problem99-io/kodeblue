# The agent engine

kodeblue's agents run inside a small agent engine: `cmd/kodeblue-engine`, shipped as the `kodeblue-engine` binary. It started as a fork of an internal coding agent and has been cut down to what kodeblue uses. kodeblue starts it as a child process and drives it over HTTP on loopback; nothing else talks to it.

This page is for people working on the engine. To run kodeblue, see [kodeblue.md](kodeblue.md).

## How kodeblue runs it

On every start, `internal/blue/runtime` (`engine.go`):

1. prepares the workspace (`/var/lib/kodeblue/workspace`): `reports/`, `notes/`, `.kodeblue/skills/` (bundled skills are refreshed, edited ones kept) and `.kodeblue/definitions/`
2. writes `config.toml` (below) next to the engine's database
3. starts the engine with `-config`, `-project <workspace>`, `-db`, `-port` and `-secrets-fd 3`, a fixed `PATH` and a private `HOME`/`TMPDIR`
4. writes one JSON object to fd 3, `{"gateway": "<model API key>", "server": "<per-start API key>"}`, and closes it. Keys never appear in argv, the environment or on disk
5. waits for `GET /v1/health`, then creates or updates its agents (`/v1/agents`), each with its own instructions, model and tool allowlist

Agents reach the host only through kodeblue's MCP server (`kodeblue mcp`, a stdio child of the engine), which exposes the `mcp__kodeblue__*` tools.

## Configuration

The engine reads exactly one TOML file, given with `-config`. Both `-config` and `-db` are required. Unknown keys are ignored.

```toml
[server]
host = "127.0.0.1"
port = 9090                      # -port overrides it

[providers.gateway]              # any OpenAI-compatible API
enabled = true
base_url = "https://api.example.com"
api_key_env = "KODEBLUE_GATEWAY_API_KEY"   # fallback; the secrets pipe wins

[agent]
max_iterations = 200             # tool-calling turns before a "keep going?" checkpoint; 0 = never
compaction_threshold_ratio = 0.8 # compact when the prompt reaches this share of the context window
compaction_model = ""            # model that writes compaction summaries; empty = the session's own model (shares its prompt cache)

[skills]
enabled = true
permissions = { "*" = "allow" }  # pattern -> allow | deny | ask

[paths]
allow_write_paths = ["."]        # relative to the project root
deny_paths = [".git", "node_modules"]

[instructions]
project_files = ["AGENTS.md"]    # added to every system prompt when present

[[mcp.servers]]
name = "kodeblue"
transport = "stdio"              # stdio | http | sse
command = "/usr/local/bin/kodeblue"
args = ["mcp", "--config", "/etc/kodeblue/kodeblue.toml"]
```

Models are discovered from the gateway's `GET /v1/models` (each entry's `provider` field groups them). A gateway that publishes no catalog still works: the provider and model a session names are registered on first use. Requests go to `<base_url>/v1/chat/completions`.

Secrets: the gateway key comes from the secrets pipe (`gateway` slot), then `api_key` in the file, then the `api_key_env` variable. `-gateway-api-key` and `-api-key` exist for standalone runs and are scrubbed from `/proc/<pid>/cmdline` right after parsing.

## Tools

| Tool | What it does |
|---|---|
| `read_file`, `list_dir` | read inside the project root |
| `write_file` | create or replace a whole file (an edit is a read followed by a full rewrite) |
| `read_definitions`, `create_definition`, `patch_definition` | the persistent notes every session sees (`.kodeblue/definitions/`); deleting one is an operator action (`DELETE /v1/definitions/{id}`) |
| `skill` | load a skill's instructions from `.kodeblue/skills/<name>/SKILL.md` |
| `ask_user` | ask a structured question; kodeblue answers on the operator's behalf |
| `mcp__<server>__<tool>` | tools from configured MCP servers |

File writes are confined to the project root, refuse symlinked parents and hard-linked targets, and go through the path policy in `internal/policy`. Writes, of files and of definitions, go to a temporary file in the same directory that is fsynced and renamed over the target, so a crash leaves either the old contents or the new, never an empty or partial file. A file owned by another user, or one the engine may not write, is never replaced. The temporary files a crash leaves behind are hidden from `list_dir` and removed when the engine next starts. An agent's `tools` list restricts it further; an empty list means every registered tool. Names that are not registered (a removed tool, an MCP server that did not connect) are logged as a warning and grant nothing, so a list that matches no registered tool leaves the agent with no tools.

## HTTP API

All routes are under `/v1` and need `Authorization: Bearer <server key>` when a key is set, except `GET /v1/health`.

| Route | Purpose |
|---|---|
| `GET /health`, `GET /build-info`, `GET /tools`, `GET /providers/models`, `GET /mcp/servers` | status and discovery |
| `POST /sessions`, `GET /sessions`, `GET /sessions/{id}` | sessions (`agent_id` or `agent_name`, optional `provider`, `model`, `instructions`, `initial_context`) |
| `POST /sessions/{id}/messages` | send a message; it starts a run, or is queued while one is active. Returns `run_id` |
| `GET /sessions/{id}/messages` | active history; `?include_reasoning=1` adds each message's reasoning |
| `GET /sessions/{id}/status`, `GET /sessions/{id}/state`, `GET /sessions/{id}/runs/{runId}/outcome` | run state and final outcome |
| `GET /sessions/{id}/events/history` | persisted events: without `include_tokens`, the latest 2000 non-streaming events; `?include_tokens=1&after_seq=N` pages through a running session live |
| `POST /sessions/{id}/abort`, `POST /sessions/{id}/compact` | stop the active run; compact now (409 while a run holds the session; disconnecting cancels it and keeps the history) |
| `GET /sessions/{id}/queue`, `PATCH`/`DELETE /sessions/{id}/queue/{itemId}`, `POST /sessions/{id}/queue/steer`, `POST /sessions/{id}/queue/continue` | the session's message queue |
| `GET /sessions/{id}/pending`, `DELETE /sessions/{id}/pending/questions/{questionId}` | `ask_user` questions waiting for an answer |
| `POST /questions/{questionId}/answer` | answer one |
| `GET`/`POST /agents`, `GET`/`PATCH`/`DELETE /agents/{agentId}` | agent definitions |
| `GET`/`POST /definitions`, `GET`/`PUT`/`DELETE /definitions/{id}` | definitions |

## Inside

- `internal/agent`: the run loop (`loop.go`), system prompt assembly, and context compaction ([compaction.md](compaction.md)). The base prompt is `internal/agent/sysprompt/base.md`; each agent's instructions follow it.
- `internal/provider`: the OpenAI-compatible streaming client, retries with backoff, model context windows.
- `internal/tools`: the tools above. `internal/mcp`: the MCP client.
- `internal/policy`: config, path rules and the tool guard that applies them.
- `internal/state`: SQLite schema and repositories (sessions, runs, messages, events, queue, questions, agents). Messages are ordered by an explicit per-session `position`, not by timestamp. Events are bounded: consecutive streamed deltas (model tokens, tool-argument fragments) are merged into one row per 250 ms, a finished run's deltas are deleted 10 minutes after it ends, and a session keeps at most 5000 events (run terminal events are always kept). Pruning starts two minutes after startup and repeats hourly, deleting in index-driven batches of 1000 rows and pausing after each for at least as long as the batch took, so a backlog never holds the database for long.
- `internal/api`: the HTTP API. `cmd/kodeblue-engine`: wiring, the run lease and the message queue.

Security properties worth knowing:
- The process marks itself non-dumpable at startup (`cmd/kodeblue-engine/harden_linux.go`), so same-uid processes cannot read its environment, file descriptors or memory through `/proc`.
- MCP server processes get an environment with known secret variables removed (`internal/childenv`).
- Each run pauses at `max_iterations` turns and asks whether to keep going; kodeblue answers from the agent's own budget.
