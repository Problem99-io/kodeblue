# Deploying kodeblue

This page covers installing the hub, adding servers, running kodeblue without a hub, upgrades, backups and removal. For locking the setup down, see [hardening.md](hardening.md). For what the hub does, see [hub.md](hub.md).

## Get the release files

Download them from [GitHub Releases](https://github.com/Problem99-io/kodeblue/releases):

- **stable**: `vX.Y.Z` releases; `releases/latest/download/<file>` always points at the newest one
- **nightly**: the rolling `nightly` pre-release, rebuilt every night that `main` changed (`releases/download/nightly/<file>`); for testing, not production

```bash
base=https://github.com/Problem99-io/kodeblue/releases/latest/download   # or …/releases/download/nightly
curl -fsSLO "$base/kodeblue-hub-linux-amd64.tar.gz" -O "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
```

Release files also carry GitHub build provenance once the repository is public: `gh attestation verify kodeblue-hub-linux-amd64.tar.gz -R Problem99-io/kodeblue` shows the commit and workflow that built them.

### Build them yourself

You need Go (the version in `go.mod`):

```bash
deploy/build-dist.sh dist
```

This produces the same files as a release:

| Path | What |
|---|---|
| `dist/agent/install.sh` | the server installer (the hub serves it at `/install.sh`) |
| `dist/agent/kodeblue-linux-{amd64,arm64}.tar.gz` | the server release: `kodeblue`, `kodeblue-engine`, `deploy/` (installer, units, example config) |
| `dist/agent/SHA256SUMS` | checksums the installer verifies downloads against |
| `dist/kodeblue-hub-linux-{amd64,arm64}.tar.gz` | hub bundles: `kodeblue-hub`, `install-hub.sh`, `kodeblue-hub.service`, and a copy of `dist/agent` as `dist/` |

Environment variables: `ARCHES="amd64"` builds one architecture, `VERSION=v1.2.3` stamps a version (default: `git describe --tags --always --dirty`). `SOURCE_DATE_EPOCH` defaults to the commit time, so with GNU tar the same commit gives byte-identical tarballs; compare yours with a release's `SHA256SUMS` to check it.

## Deploy the hub

The hub needs one TLS mode. Pick one:

| Mode | Flags | When |
|---|---|---|
| Self-signed, pinned | `--self-signed` | No domain or CA needed. Servers pin the hub's public key. Browsers show a warning. |
| Your certificate | `--tls-cert f --tls-key f` | You have a certificate for the hub's name. |
| Reverse proxy | `--behind-proxy` | Caddy, nginx or similar terminates TLS and forwards plain HTTP to the hub. |

Without one of these, the hub refuses to start unless it listens on a loopback address.

`--public-url` is the URL that servers and browsers use to reach the hub. It goes into the install commands the hub prints. It must be `https://` (plain `http://` only to localhost), and `--behind-proxy` requires an `https://` public URL.

### On a Linux host with systemd

```bash
scp dist/kodeblue-hub-linux-amd64.tar.gz hub.example.com:
ssh -t hub.example.com
tar xzf kodeblue-hub-linux-amd64.tar.gz
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com:8443 --self-signed
```

Other modes:

```bash
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com --tls-cert /etc/ssl/hub.crt --tls-key /etc/ssl/hub.key --listen :443
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com --behind-proxy --listen 127.0.0.1:8080
```

`install-hub.sh` options:

| Option | Effect |
|---|---|
| `--public-url URL` | required, must be `https://` |
| `--listen ADDR` | listen address (default `:8443`) |
| `--self-signed` | generate a certificate in `/var/lib/kodeblue-hub/tls`; servers pin its public key |
| `--tls-cert F --tls-key F` | copy your certificate to `/etc/kodeblue-hub/tls.{crt,key}` (root:kodeblue-hub 0640) |
| `--behind-proxy` | plain HTTP behind a TLS-terminating proxy |
| `--trusted-proxy LIST` | with `--behind-proxy`: addresses/CIDRs of the proxies whose `X-Forwarded-For` is believed (default loopback) |
| `--console-allow LIST` | only these addresses/CIDRs reach the console and operator API; servers can always enroll and sync |
| `--http-listen ADDR` | extra plain-HTTP console listener on a loopback address, for an SSH tunnel |
| `--admin NAME` | name of the first operator account (default `admin`) |

The installer:
1. creates the `kodeblue-hub` system user
2. installs `/usr/local/bin/kodeblue-hub`
3. creates `/var/lib/kodeblue-hub` (0700) and copies the agent release to `/var/lib/kodeblue-hub/dist`
4. writes `/etc/kodeblue-hub/env` (root:kodeblue-hub 0640) with the `KODEBLUE_HUB_*` settings
5. installs `/etc/systemd/system/kodeblue-hub.service` (sandboxed: `ProtectSystem=strict`, `NoNewPrivileges`, only `CAP_NET_BIND_SERVICE`)
6. asks for the first operator's password if there is no operator yet (use `ssh -t`: it reads from the terminal)
7. enables and starts the service, and prints the pin when self-signed

Logs: `journalctl -fu kodeblue-hub`. Health: `GET /healthz` returns `ok`.

Running `install-hub.sh` again rewrites the `KODEBLUE_HUB_*` keys for the TLS mode and addresses (`DATA`, `LISTEN`, `PUBLIC_URL`, `SELF_SIGNED`, `BEHIND_PROXY`, `TLS_CERT`, `TLS_KEY`) in `/etc/kodeblue-hub/env`, so pass the same mode and `--public-url` again. `TRUSTED_PROXIES`, `CONSOLE_ALLOW` and `HTTP_LISTEN` change only when you pass their option; otherwise the existing value is kept. Other lines you added are kept too.

### With Docker

Use the released image, `ghcr.io/problem99-io/kodeblue-hub` (`:latest` or `:vX.Y.Z` for stable releases, `:nightly` for testing; amd64 and arm64). It contains the hub and the agent release for amd64 and arm64 (in `/opt/kodeblue-hub/dist`), so the hub can serve installs on its own. To build it yourself instead, from the repository root:

```bash
docker build -f deploy/hub/Dockerfile -t kodeblue-hub .
```

The examples below use the image name `kodeblue-hub`; replace it with `ghcr.io/problem99-io/kodeblue-hub:latest` for the released image.

Behind a reverse proxy on the same host:

```bash
docker run -d --name kodeblue-hub --restart unless-stopped -v kodeblue-hub:/data \
  -p 127.0.0.1:8080:8080 \
  -e KODEBLUE_HUB_PUBLIC_URL=https://hub.example.com -e KODEBLUE_HUB_BEHIND_PROXY=1 -e KODEBLUE_HUB_LISTEN=:8080 \
  -e KODEBLUE_HUB_TRUSTED_PROXIES=172.16.0.0/12 \
  kodeblue-hub
```

Inside the container, a proxy on the host (or in another container) connects from the Docker bridge, for example `172.17.0.1`, not from loopback. `KODEBLUE_HUB_TRUSTED_PROXIES` must cover that address, or the hub ignores `X-Forwarded-For` and every client looks like the bridge gateway, sharing one sign-in throttle. `172.16.0.0/12` covers Docker's default bridge networks; use your bridge's exact subnet (`docker network inspect bridge`) to be stricter.

With its own self-signed certificate:

```bash
docker run -d --name kodeblue-hub --restart unless-stopped -v kodeblue-hub:/data -p 8443:8443 \
  -e KODEBLUE_HUB_PUBLIC_URL=https://hub.example.com:8443 -e KODEBLUE_HUB_SELF_SIGNED=1 \
  kodeblue-hub
docker exec kodeblue-hub kodeblue-hub pin
```

First operator:

```bash
docker exec -it kodeblue-hub kodeblue-hub user add admin
```

The container runs as uid 10001. All state is in the `/data` volume. Publish the port on `127.0.0.1` when a proxy on the host sits in front: in `--behind-proxy` mode the hub speaks plain HTTP, so it must not be reachable directly. Docker's published ports bypass ufw and most host `INPUT` rules; see [hardening.md](hardening.md#docker).

### Behind a reverse proxy

Run the hub with `--behind-proxy` on a loopback address, and let the proxy terminate TLS:

```bash
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com --behind-proxy --listen 127.0.0.1:8080
```

How the hub reads forwarded headers:
- It believes `X-Forwarded-For` only in `--behind-proxy` mode, and only on connections from a trusted proxy: `--trusted-proxy` (`KODEBLUE_HUB_TRUSTED_PROXIES`), default loopback (`127.0.0.0/8`, `::1`). From any other peer the header is ignored and the peer address is the client, so a client that reaches the hub directly cannot spoof its address.
- The client is the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy. Several headers are read as one list. If an entry is not a valid address, the hub uses the peer address.
- It uses that address for the sign-in and enrollment throttles, `--console-allow`, the audit log and each server's last-seen IP. It reads no other forwarded header.
- `--trusted-proxy` without `--behind-proxy` is refused at start.
- Still listen on `127.0.0.1` (or a private address only the proxy can reach): the hub speaks plain HTTP in this mode.
- Cookies are `Secure` with the `__Host-` prefix, and the hub sends HSTS.
- Servers hold a long-poll open for up to about 50 seconds (`GET /api/agent/v1/messages?wait=50`). The proxy's read timeout must be longer than that.
- A server's sync request can be up to 16 MiB. Raise the proxy's body limit.

Caddy (it sets `X-Forwarded-For` to the client address itself and has no default response timeout):

```
hub.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name hub.example.com;

    ssl_certificate     /etc/letsencrypt/live/hub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hub.example.com/privkey.pem;

    client_max_body_size 20m;        # sync bodies are capped at 16 MiB by the hub
    proxy_read_timeout   90s;        # the message long-poll waits up to ~50 s

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # the client, as nginx saw it
    }
}

server {
    listen 80;
    server_name hub.example.com;
    return 301 https://$host$request_uri;
}
```

If a load balancer sits in front of the proxy, either let the proxy append to the header (nginx: `$proxy_add_x_forwarded_for`) and add the load balancer's addresses to `--trusted-proxy`, or have the proxy resolve the real client first (nginx: the `realip` module). The hub walks the list from the right and skips every trusted proxy. If you get this wrong, every request appears to come from the load balancer, and one sign-in throttle covers all users.

Make sure the proxy always sets `X-Forwarded-For`. Without it, proxied requests carry the proxy's own address, and if that address is in `--console-allow` (for example `127.0.0.1` for an SSH tunnel), everyone coming through the proxy would pass.

To expose only the agent API publicly and keep the console private, see [hardening.md](hardening.md#keep-the-console-off-the-public-internet).

### Behind Cloudflare

For a hub that servers reach over the internet, we recommend putting it behind Cloudflare with a `cloudflared` tunnel:
- **No open port.** `cloudflared` dials out to Cloudflare, so the hub host needs no inbound rule at all.
- **A public certificate.** Servers verify Cloudflare's certificate like any HTTPS client; no pin, nothing to renew.
- **Cloudflare in front of the console.** DDoS protection, the WAF, and Cloudflare Access for operator sign-in.

Know the trade-off: Cloudflare terminates TLS at its edge, so it can read the traffic between your servers and the hub (incidents, findings, agent transcripts). If no third party may see it, keep the hub on WireGuard ([hardening.md](hardening.md#wireguard-the-hub-on-a-private-network)) or serve TLS from the hub itself.

**1. The hub** on loopback, in proxy mode:

```bash
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com --behind-proxy --listen 127.0.0.1:8080
```

**2. The tunnel.** Install `cloudflared` on the hub host, then either create the tunnel in the Cloudflare dashboard (Zero Trust → Networks → Tunnels: add a public hostname `hub.example.com` with service `http://127.0.0.1:8080`, then run the `sudo cloudflared service install <token>` command it shows), or from the command line:

```bash
cloudflared tunnel login
cloudflared tunnel create kodeblue-hub        # writes ~/.cloudflared/<tunnel-id>.json
cloudflared tunnel route dns kodeblue-hub hub.example.com
sudo mkdir -p /etc/cloudflared && sudo cp ~/.cloudflared/<tunnel-id>.json /etc/cloudflared/
```

`/etc/cloudflared/config.yml`:

```yaml
tunnel: kodeblue-hub
credentials-file: /etc/cloudflared/<tunnel-id>.json
ingress:
  - hostname: hub.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

```bash
sudo cloudflared service install
```

**3. Cloudflare settings** for the zone: SSL/TLS **Always Use HTTPS** on, **Minimum TLS Version** 1.2 or higher.

**4. Enroll servers** with the command from **Add server**, without `--pin`.

How this fits the hub:
- `cloudflared` connects from `127.0.0.1`, which the hub trusts for `X-Forwarded-For` by default. Cloudflare appends the client's address to that header and the hub reads the rightmost untrusted entry, so sign-in throttles, `--console-allow` and the audit log see the real client.
- The message long-poll waits up to about 50 seconds, under Cloudflare's 100-second limit for a proxied request. Sync bodies (up to 16 MiB) are far below its upload limit.
- Do not pin. Cloudflare's edge certificate comes from a public CA and changes on renewal. A server enrolled with a pin to a self-signed hub must be re-enrolled without one when you move the hub behind Cloudflare.
- Servers are not browsers. If Bot Fight Mode or a challenge applies to the hub's hostname, servers fail to sync. Leave them off for this hostname, or exempt the agent paths (`/api/agent/v1/*`, `/install.sh`, `/dist/*`) where your plan allows it. The same goes for WAF managed rules: sync bodies carry the evidence of attacks (commands, request lines), which a WAF may block. Skip the managed rules for the agent paths.
- **Cloudflare Access** for the console: add a self-hosted Access application for `hub.example.com` with your sign-in policy, and a second one for the agent paths with a **Bypass** policy, since servers cannot sign in interactively. The hub's own operator sign-in still applies behind Access.
- With Docker, run `cloudflared` in a container on the same network as the hub, publish no port, and set `KODEBLUE_HUB_TRUSTED_PROXIES` to that network's subnet, since `cloudflared` then connects from the Docker network rather than loopback.

Cloudflare's proxy without a tunnel also works: serve the hub with a certificate (a Cloudflare Origin CA certificate, or a reverse proxy in front of it), set SSL/TLS to **Full (strict)**, allow inbound HTTPS only from [Cloudflare's address ranges](https://www.cloudflare.com/ips/), and list those ranges in `--trusted-proxy`. The tunnel is simpler and opens no port.

### Self-signed with a pin

With `--self-signed`, the hub creates an ECDSA P-256 key and a 10-year certificate in `<data>/tls/` (`cert.pem`, `key.pem`) on first start. The certificate names `localhost`, `127.0.0.1`, the host name and the host from `--public-url`. The key is kept across restarts, so the pin stays valid.

Print the pin:

```bash
sudo -u kodeblue-hub kodeblue-hub pin --data /var/lib/kodeblue-hub
```

The pin is `sha256//` plus the base64 SHA-256 of the certificate's public key, the same format as curl's `--pinnedpubkey`. The install commands the hub prints include it twice: for curl (`-k --pinnedpubkey`) and for kodeblue (`--pin`). Servers store it in `[hub] pin` and accept only that key.

Browsers do not know the pin and will warn. Compare the certificate fingerprint your browser shows with the one on the hub before you accept it:

```bash
sudo openssl x509 -in /var/lib/kodeblue-hub/tls/cert.pem -noout -fingerprint -sha256
```

### All hub settings

`kodeblue-hub serve` flags and their environment variables:

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--data` | `KODEBLUE_HUB_DATA` | `/var/lib/kodeblue-hub` | data directory (`hub.db`, `tls/`, `dist/`) |
| `--listen` | `KODEBLUE_HUB_LISTEN` | `:8443` | main listener: console, agent API, installer |
| `--tls-cert`, `--tls-key` | `KODEBLUE_HUB_TLS_CERT`, `KODEBLUE_HUB_TLS_KEY` | | your certificate (PEM) |
| `--self-signed` | `KODEBLUE_HUB_SELF_SIGNED=1` | off | generate and pin a certificate |
| `--behind-proxy` | `KODEBLUE_HUB_BEHIND_PROXY=1` | off | plain HTTP behind a TLS proxy |
| `--trusted-proxy` | `KODEBLUE_HUB_TRUSTED_PROXIES` | loopback | with `--behind-proxy`: proxies whose `X-Forwarded-For` is believed (comma- or space-separated addresses/CIDRs) |
| `--console-allow` | `KODEBLUE_HUB_CONSOLE_ALLOW` | everyone | addresses/CIDRs that may reach the console and operator API; others get a 404 |
| `--endpoint-allow` | `KODEBLUE_HUB_ENDPOINT_ALLOW` | none | loopback, link-local or metadata addresses/CIDRs the hub itself may reach model endpoints at (connection test, model browser), e.g. `127.0.0.1` for a gateway on the hub host; private LAN ranges are always allowed ([hub.md](hub.md#connection-and-security-model)) |
| `--public-url` | `KODEBLUE_HUB_PUBLIC_URL` | | URL servers and browsers use |
| `--dist` | `KODEBLUE_HUB_DIST` | `<data>/dist` | release files served to installers |
| `--http-listen` | `KODEBLUE_HUB_HTTP_LISTEN` | | extra plain-HTTP listener, loopback addresses only |
| `--enroll-ttl` | (none) | `2h` | lifetime of one-time enrollment tokens |

`--http-listen` serves the same routes as the main listener (console and agent API). It exists for an SSH tunnel to the console.

`--console-allow` applies to every listener, `--http-listen` included. Requests to `/api/agent/v1/*`, `/install.sh`, `/dist/*` and `/healthz` are always let through, so servers can enroll, sync and upgrade from anywhere; everything else returns a plain 404 to addresses outside the list. Over an SSH tunnel the client is `127.0.0.1`, so add `127.0.0.1` (or `::1`) to the list. See [hardening.md](hardening.md#keep-the-console-off-the-public-internet).

## Create operator accounts

`install-hub.sh` creates the first account. More accounts, password resets and removals use the CLI on the hub host. Run it as the `kodeblue-hub` user so file ownership stays right:

```bash
sudo -u kodeblue-hub kodeblue-hub user add alice --data /var/lib/kodeblue-hub   # prompts for the password (min 12 chars)
sudo -u kodeblue-hub kodeblue-hub user list --data /var/lib/kodeblue-hub
sudo -u kodeblue-hub kodeblue-hub user del alice --data /var/lib/kodeblue-hub
```

The password is read from stdin (without echo on a terminal). `user add` for an existing name sets a new password and signs that user out everywhere. With Docker: `docker exec -it kodeblue-hub kodeblue-hub user add alice`.

## Add servers

### From the console

1. Optional, once: in **Settings**, add a model connection and pick the default model. New servers receive it, with its key, when they enroll.
2. **Add server**, give it a name. The hub shows a one-line command with a single-use token (`kbe_…`), valid for 2 hours by default (`--enroll-ttl`).
3. Run the command on the server, as a user who can `sudo`:

```bash
f=$(mktemp) && { curl -fsSL --proto =https --proto-redir =https -o "$f" https://hub.example.com/install.sh && echo "<sha256>  $f" | sha256sum -c - && sudo sh "$f" --hub https://hub.example.com --token kbe_…; s=$?; rm -f "$f"; (exit "$s"); }
```

For a self-signed hub the command also carries the pin (`curl -k --pinnedpubkey sha256//…` and `--pin sha256//…`). When the hub's installer reads the token from stdin, the command pipes it in as `printf '%s\n' kbe_… | sudo sh "$f" … --token-file -` instead of `--token`, so the token is on no command line. Copy the command from the console rather than typing it: `<sha256>` is the hash of the `install.sh` this hub serves. The command saves the script, checks that hash, and only then runs it as root. The script in turn carries the hash of each release tarball.

The installer downloads the release from the hub with the token, checks it against the hash pinned in the script, installs it, enrolls (trading the token for the server's own `kbk_…` key in `/etc/kodeblue/hub.key`) and starts kodeblue. The server shows as online in the console within seconds.

#### Keep the token out of your shell history

The token is part of the line you paste, so your shell saves it to its history file. Once the install has enrolled the server the token is worthless: it is single-use. Until then, for up to 2 hours, anyone who can read that history could enroll a machine in this server's place. We recommend keeping the line out of the history:

- **bash:** start the line with a space. That skips it when `HISTCONTROL` is `ignorespace` or `ignoreboth` (Ubuntu's default, and Debian's for user accounts but not root). Check with `echo $HISTCONTROL`, and if it shows neither, run `export HISTCONTROL=ignorespace` first.
- **zsh:** run `setopt HIST_IGNORE_SPACE` first, then start the line with a space.

If the line was saved anyway, delete it once the install is done: in bash, find its number with `history | tail`, then `history -d <number> && history -w`; in other shells, remove it from the history file (`~/.bash_history`, `~/.zsh_history`, …). If the install did not complete, click **New install token** on the server in the console: a new token cancels the old one.

From the hub host's CLI instead of the console:

```bash
sudo -u kodeblue-hub kodeblue-hub server add web-1 --public-url https://hub.example.com --data /var/lib/kodeblue-hub
```

### Installer options

| Option | Effect |
|---|---|
| `--hub URL` | hub to connect to (`https://`) |
| `--token T` | one-time enrollment token |
| `--pin sha256//…` | the hub's certificate pin (self-signed hub) |
| `--ca-file F` | CA certificate that signed the hub's certificate (private CA). Also pass curl `--cacert F` when fetching `install.sh`. |
| `--name NAME` | server name in its own config (the hub shows the name given in **Add server**) |
| `--mode off\|recommend\|contain` | response policy for a new install (default `recommend`); ignored when `/etc/kodeblue/kodeblue.toml` exists |
| `--inference-url URL`, `--model M` | the server's own model endpoint and model |
| `--inference-key-file F` | file holding the endpoint's API key |
| `--slack-webhook-file F` | Slack incoming webhook, only for servers without a hub |
| `--no-start` | install and enroll, but do not start the services |
| `--uninstall [--purge]` | remove kodeblue |

The model endpoint is taken from the flags first, then from the hub's default at enrollment, then from a prompt. Without one, the model layers stay off; sensors, detection and monitors run, and the learning session and vulnerability assessment wait until a model is set (the hub shows this), then start on their own.

### Re-enroll or rotate a server's key

In the console, **New install token** on the server creates a fresh token. Running the install command with it gives the server a new key; the old key stops working once the token is used. **Revoke key** cuts a server off at once. **Delete** removes the server and everything the hub stored for it; kodeblue on the server keeps running but can no longer reach the hub.

### Manual enrollment

On a server that already runs kodeblue:

```bash
sudo KODEBLUE_ENROLL_TOKEN=kbe_… kodeblue enroll --hub https://hub.example.com [--pin 'sha256//…'] [--ca-file f] [--name web-1]
sudo systemctl restart kodeblue
```

The token is read from the environment so it stays out of the process list.

## Without a hub

From an unpacked server release:

```bash
tar xzf kodeblue-linux-amd64.tar.gz
sudo ./kodeblue/deploy/install.sh --inference-url https://api.example.com --model <model> \
  [--inference-key-file key.txt] [--slack-webhook-file hook.txt] [--mode recommend]
```

Without `--inference-key-file` and `--slack-webhook-file`, the installer asks for both on the terminal. Then review `/etc/kodeblue/kodeblue.toml` (see `deploy/kodeblue.toml.example`) and restart: `sudo systemctl restart kodeblue`.

What gets installed:

| Path | What |
|---|---|
| `/usr/local/bin/kodeblue`, `/usr/local/lib/kodeblue/engine` | binaries |
| `/etc/kodeblue/` (root:kodeblue 0750) | `kodeblue.toml`, `inference.key`, `hub.key`, `slack.webhook` (all root:kodeblue 0640) |
| `/var/lib/kodeblue/` (kodeblue 0750) | database, agent workspace, `response/` (root:kodeblue 0750) |
| `kodeblue.service` | the daemon, as non-root user `kodeblue` with capabilities to read the whole host (see [kodeblue.md](kodeblue.md#running-as-its-own-user)) |
| `kodeblue-respond.socket`, `kodeblue-respond@.service` | the root containment helper, one process per request, on `/run/kodeblue/respond.sock` |

## Upgrades

### Hub

On a systemd host, download the new hub bundle (or build it), unpack it and run `install-hub.sh` again **with the same options** as the first time:

```bash
tar xzf kodeblue-hub-linux-amd64.tar.gz
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com:8443 --self-signed
```

It replaces the binary, the unit file, its managed keys in `/etc/kodeblue-hub/env` (lines you added yourself are kept) and the agent release in `/var/lib/kodeblue-hub/dist`, then restarts the hub. It does not touch operators, servers or the self-signed key. The database schema is migrated automatically on start.

With Docker, pull the new image (`docker pull ghcr.io/problem99-io/kodeblue-hub:latest`) and recreate the container with the same volume and environment.

Take a backup first (below).

### Servers

Upgrade the hub first: servers download their new release from it. Then, on each server, run the install command **without `--token`**. The installer authenticates with the server's own key:

```bash
curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --hub https://hub.example.com
# self-signed hub:
curl -fsSL -k --pinnedpubkey 'sha256//…' https://hub.example.com:8443/install.sh \
  | sudo sh -s -- --hub https://hub.example.com:8443 --pin 'sha256//…'
```

Without a hub, unpack the new release and run `sudo ./kodeblue/deploy/install.sh` again.

An upgrade:
- opens a journaled 10-minute maintenance window first, so kodeblue replacing its own binaries is not reported as tampering
- replaces the binaries and the systemd units, and restarts kodeblue
- keeps `/etc/kodeblue/kodeblue.toml`, the keys and all state (`--mode` is not applied to an existing config)
- migrates kodeblue's database on start and refreshes the bundled skills; skills the agents wrote are kept

Servers do not upgrade themselves. The hub shows each server's version.

## Backups

| Where | What | Notes |
|---|---|---|
| Hub: `/var/lib/kodeblue-hub/` | `hub.db` (+ `-wal`, `-shm`), `tls/` | Operators, servers, records, settings, model connection keys, Slack webhook, audit log. `tls/key.pem` is what servers pin. `dist/` can be rebuilt. |
| Hub: `/etc/kodeblue-hub/` | `env`, `tls.crt`, `tls.key` | systemd installs only |
| Hub (Docker): the `/data` volume | same as `/var/lib/kodeblue-hub` | |
| Server: `/etc/kodeblue/` | `kodeblue.toml`, `inference.key`, `hub.key`, `slack.webhook` | the policy and the credentials |
| Server: `/var/lib/kodeblue/` | `kodeblue.db` (baseline, findings, incidents, spend), `workspace/` (reports, skills, definitions), `response/` (action records, quarantined files, backups of disabled SSH key files in `response/ssh-keys/`), `hub-settings.json` | |

The hub database uses SQLite in WAL mode. For a consistent copy, stop the hub briefly:

```bash
sudo systemctl stop kodeblue-hub
sudo tar czf /root/kodeblue-hub-$(date +%F).tgz -C / var/lib/kodeblue-hub etc/kodeblue-hub
sudo systemctl start kodeblue-hub
```

Or, with the `sqlite3` tool installed, copy it online: `sudo sqlite3 /var/lib/kodeblue-hub/hub.db ".backup '/root/hub-$(date +%F).db'"`.

Backups contain credentials in plain form: model connection keys and the Slack webhook (hub), and `hub.key` and `inference.key` (servers). Encrypt them and restrict who can read them. A server's state is specific to that host; restore it only onto the same server.

## Uninstall

### A server

Undo any containment that is still active first (`sudo kodeblue respond list`, then `sudo kodeblue respond undo <id>`). Then:

```bash
curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --uninstall           # keeps /etc/kodeblue and /var/lib/kodeblue
curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --uninstall --purge   # also removes config, state and the kodeblue user
```

Or run `sudo ./kodeblue/deploy/install.sh --uninstall [--purge]` from a release directory. `--purge` also deletes quarantined files and SSH key backups. Then **Revoke key** or **Delete** the server in the console.

### The hub

There is no uninstall script. On a systemd host:

```bash
sudo systemctl disable --now kodeblue-hub
sudo rm -f /etc/systemd/system/kodeblue-hub.service /usr/local/bin/kodeblue-hub
sudo rm -rf /etc/systemd/system/kodeblue-hub.service.d /etc/kodeblue-hub /var/lib/kodeblue-hub
sudo systemctl daemon-reload
sudo userdel kodeblue-hub
```

With Docker: `docker rm -f kodeblue-hub && docker volume rm kodeblue-hub`.

Servers keep running on their own after the hub is gone. Their notifications wait in a local outbox. Remove `[hub]` from `/etc/kodeblue/kodeblue.toml` and set a local webhook to have them post to Slack directly.
