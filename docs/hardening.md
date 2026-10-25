# Hardening kodeblue

Concrete steps to lock down a kodeblue deployment. Read [deploy.md](deploy.md) first for the basic setup and [hub.md](hub.md) for the security model.

Addresses in the examples:

| Address | Role |
|---|---|
| `203.0.113.10` | the hub's public address |
| `198.51.100.0/24` | your servers |
| `192.0.2.0/28` | your operators (VPN egress) |
| `203.0.113.7` | an operator office address |
| `10.66.0.0/24` | a private WireGuard network (hub `10.66.0.1`) |

## What talks to what

| From | To | Why |
|---|---|---|
| each server | hub, HTTPS | enrollment, sync every 15 s, message long-poll, installer downloads |
| operators' browsers | hub, HTTPS | the console |
| each server | its model endpoint, HTTPS | triage and agent sessions |
| hub | Slack, HTTPS | posting notifications |
| hub | model connections, HTTPS | listing models and the connection test in **Settings** |
| server (`[notify] direct = true`, or no hub) | Slack, HTTPS | posting notifications |

The hub never connects to a server, and nothing on a server listens for the hub. Servers need no inbound rule for kodeblue. Servers honor `HTTPS_PROXY` for their connection to the hub.

All of it is TLS 1.2 or newer:
- A server refuses a hub URL that is not `https://` (plain `http://` only to `localhost`, for testing), and never follows a redirect, so a proxy cannot downgrade it or send its credential elsewhere.
- The installer's downloads from the hub and the enroll command the hub prints use only HTTPS, redirects included.
- The hub refuses to serve plain HTTP on any address but loopback, unless `--behind-proxy` says a TLS-terminating proxy sits in front, and then it needs an `https://` public URL.

For a hub on the internet, we recommend a Cloudflare tunnel in front of it ([deploy.md](deploy.md#behind-cloudflare)): no open port on the hub host, a public certificate, and Cloudflare Access in front of the console. Cloudflare then sees the traffic between servers and the hub; WireGuard ([below](#wireguard-the-hub-on-a-private-network)) keeps it to your own network.

## Keep the console off the public internet

### `--console-allow`

`--console-allow LIST` (`KODEBLUE_HUB_CONSOLE_ALLOW`) takes comma- or space-separated addresses and CIDRs. When it is set, the hub answers every request from other client addresses with a plain 404, except the paths servers need:

- `/api/agent/v1/*` (enroll, sync, messages)
- `/install.sh` and `/dist/*` (installs and upgrades)
- `/healthz`

So servers can enroll, sync and upgrade from anywhere, and the console, the operator API and the sign-in form do not exist for anyone else. The check applies on every listener, `--http-listen` included. The client address is the TCP peer, or, with `--behind-proxy`, the address from `X-Forwarded-For` as sent by a trusted proxy (see [deploy.md](deploy.md#behind-a-reverse-proxy)); a client cannot spoof it by sending its own header.

### Recipe: servers over the internet, console from the office and WireGuard

The hub is public for servers on `203.0.113.10:8443`. Operators reach the console from the office address `203.0.113.7` or over WireGuard (`10.66.0.0/24`, set up as in the WireGuard section below, but with the hub listening on all addresses):

```bash
sudo kodeblue-hub/install-hub.sh --public-url https://hub.example.com:8443 --self-signed \
  --console-allow 203.0.113.7,10.66.0.0/24
```

That runs `kodeblue-hub serve --self-signed --public-url https://hub.example.com:8443 --console-allow 203.0.113.7,10.66.0.0/24` on `:8443`. Check it from an address outside the list:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://hub.example.com:8443/          # 404
curl -sk -o /dev/null -w '%{http_code}\n' https://hub.example.com:8443/healthz   # 200
```

An operator on WireGuard must reach the hub through the tunnel, or the hub sees the laptop's public address. Browse to `https://10.66.0.1:8443`, or map the hub's name to its tunnel address on the laptop (`10.66.0.1 hub.example.com` in `/etc/hosts`) so the certificate name still matches.

Behind a reverse proxy the same works with `--behind-proxy --listen 127.0.0.1:8080 --console-allow 203.0.113.7,10.66.0.0/24`. If operators also use an SSH tunnel to the hub's loopback listener, add `127.0.0.1`. Then the proxy must always set `X-Forwarded-For` (Caddy does; nginx needs the `proxy_set_header` line), or proxied requests would arrive as `127.0.0.1` and pass.

Re-running `install-hub.sh` (for an upgrade) keeps the existing `KODEBLUE_HUB_CONSOLE_ALLOW` unless you pass `--console-allow` again; to remove the limit, delete the line from `/etc/kodeblue-hub/env` and restart the hub.

### SSH tunnel

With `--http-listen 127.0.0.1:8081`, the hub adds a plain-HTTP listener on loopback. Include `127.0.0.1` in `--console-allow`, since the gate applies there too:

```bash
ssh -N -L 8081:127.0.0.1:8081 admin@hub.example.com
# then open http://localhost:8081
```

The session cookie is marked `Secure` when the hub uses TLS or a proxy. Current Chrome and Firefox accept `Secure` cookies on `http://localhost`; use `localhost`, not another name. If your browser does not, use WireGuard.

### More layers

- **WireGuard for everything** ([below](#wireguard-the-hub-on-a-private-network)) is the strongest option: nothing of the hub is public, not even the agent API.
- **Cloudflare Access** in front of the console, with a bypass for the agent paths ([deploy.md](deploy.md#behind-cloudflare)), adds Cloudflare's sign-in before the hub's own.
- **Firewall and proxy filtering** (below) add a second check that does not depend on the hub. For example, a proxy that forwards only the agent paths and answers everything else itself:

  ```
  hub.example.com {
  	@agent path /api/agent/v1/* /install.sh /dist/*
  	handle @agent {
  		reverse_proxy 127.0.0.1:8080
  	}
  	handle {
  		respond 404
  	}
  }
  ```

## Network: restrict who reaches the hub

Defence in depth on top of `--console-allow`. The hub needs inbound connections from two groups only: your servers (agent API and installer) and your operators (console). Allow those at the firewall or the proxy and drop the rest.

### nftables

A separate table composes with an existing firewall: a `drop` here is final, and an `accept` here does not override drops elsewhere. Save as `/etc/nftables.d/kodeblue-hub.nft`:

```
table inet kodeblue_hub
delete table inet kodeblue_hub

table inet kodeblue_hub {
	set servers4 {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.0/24 }
	}
	set operators4 {
		type ipv4_addr
		flags interval
		elements = { 192.0.2.0/28 }
	}
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 8443 ip saddr @servers4 accept
		tcp dport 8443 ip saddr @operators4 accept
		tcp dport 8443 drop
	}
}
```

The first two lines make the file safe to load again. The final `drop` also covers IPv6, since the table is `inet`; add `ipv6_addr` sets if you need IPv6 sources. Load and persist it:

```bash
sudo nft -f /etc/nftables.d/kodeblue-hub.nft
echo 'include "/etc/nftables.d/kodeblue-hub.nft"' | sudo tee -a /etc/nftables.conf
sudo systemctl enable nftables
```

Use the port your hub (or its proxy) listens on: `8443` by default, `443` behind a proxy.

### ufw

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH                       # keep your own access first
sudo ufw allow from 198.51.100.0/24 to any port 8443 proto tcp
sudo ufw allow from 192.0.2.0/28 to any port 8443 proto tcp
sudo ufw enable
```

### Docker

Ports that Docker publishes bypass ufw and most `INPUT` rules. Do not publish the hub on all addresses. Publish it only on loopback with a proxy on the host in front (`-p 127.0.0.1:8080:8080`), or only on a private address such as the WireGuard address (`-p 10.66.0.1:8443:8443`). `KODEBLUE_HUB_CONSOLE_ALLOW` works in a container like any other setting.

Behind a proxy, the hub inside the container sees the Docker bridge gateway (for example `172.17.0.1`) as its peer, not loopback. Set `KODEBLUE_HUB_TRUSTED_PROXIES=172.16.0.0/12` (or your bridge's exact subnet), or the hub ignores `X-Forwarded-For`: every client then looks like the gateway, they share one sign-in throttle, and `--console-allow` cannot tell them apart.

### At the reverse proxy

Filter by the TCP peer address. Do not filter on `X-Forwarded-For` or other headers the client can set.

Caddy (`remote_ip` matches the direct peer):

```
hub.example.com {
	@servers {
		path /api/agent/v1/* /install.sh /dist/*
		remote_ip 198.51.100.0/24
	}
	handle @servers {
		reverse_proxy 127.0.0.1:8080
	}

	@operators remote_ip 192.0.2.0/28
	handle @operators {
		reverse_proxy 127.0.0.1:8080
	}

	handle {
		respond 403
	}
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name hub.example.com;
    ssl_certificate     /etc/letsencrypt/live/hub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hub.example.com/privkey.pem;

    client_max_body_size 20m;
    proxy_read_timeout   90s;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;

    # Agent API and installer: servers only.
    location ~ ^/(api/agent/v1/|dist/|install\.sh$) {
        allow 198.51.100.0/24;
        deny  all;
        proxy_pass http://127.0.0.1:8080;
    }

    # Console and operator API: operators only.
    location / {
        allow 192.0.2.0/28;
        deny  all;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

`--console-allow` limits only the console and operator API. Limiting which addresses reach the agent API and the installer still takes the firewall or the proxy.

## WireGuard: the hub on a private network

In this setup the hub listens only on its WireGuard address. Servers and operator laptops are WireGuard peers. The only public port on the hub is WireGuard's UDP port.

```
 server web-1  10.66.0.11 ─┐
 server web-2  10.66.0.12 ─┼── udp/51820 ──► hub 203.0.113.10, wg0 10.66.0.1 ── kodeblue-hub on 10.66.0.1:8443
 laptop        10.66.0.100 ┘
```

### 1. Keys

On each machine (hub, every server, every laptop):

```bash
sudo apt install wireguard-tools        # or your distribution's package
sudo sh -c 'umask 077; wg genkey > /etc/wireguard/wg0.key; wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub'
sudo cat /etc/wireguard/wg0.pub         # share the public key; the private key never leaves the machine
```

### 2. The hub (wg-quick)

`/etc/wireguard/wg0.conf` (mode 0600):

```ini
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = <contents of the hub's /etc/wireguard/wg0.key>

# web-1
[Peer]
PublicKey = <web-1 public key>
AllowedIPs = 10.66.0.11/32

# web-2
[Peer]
PublicKey = <web-2 public key>
AllowedIPs = 10.66.0.12/32

# alice's laptop
[Peer]
PublicKey = <laptop public key>
AllowedIPs = 10.66.0.100/32
```

```bash
sudo systemctl enable --now wg-quick@wg0
```

Leave IP forwarding off on the hub (`sysctl net.ipv4.ip_forward` should print `0`). Then peers can reach the hub but not each other.

### 3. Each server and laptop

`/etc/wireguard/wg0.conf` on `web-1`:

```ini
[Interface]
Address = 10.66.0.11/32
PrivateKey = <contents of web-1's /etc/wireguard/wg0.key>

[Peer]
PublicKey = <hub public key>
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.66.0.1/32
PersistentKeepalive = 25
```

```bash
sudo systemctl enable --now wg-quick@wg0
ping -c1 10.66.0.1
```

`AllowedIPs = 10.66.0.1/32` routes only the hub through the tunnel; the server's other traffic is unchanged. `PersistentKeepalive = 25` keeps the tunnel open for servers behind NAT or a stateful firewall. A laptop uses the same file with its own address (`10.66.0.100/32`).

On a server, kodeblue does not need the tunnel at boot: its hub link retries with backoff (5 s up to 5 minutes) until the hub answers.

### 4. systemd-networkd instead of wg-quick

On the hub, `/etc/systemd/network/50-wg0.netdev`:

```ini
[NetDev]
Name=wg0
Kind=wireguard

[WireGuard]
PrivateKeyFile=/etc/systemd/network/wg0.key
ListenPort=51820

[WireGuardPeer]
PublicKey=<web-1 public key>
AllowedIPs=10.66.0.11/32
```

`/etc/systemd/network/50-wg0.network`:

```ini
[Match]
Name=wg0

[Network]
Address=10.66.0.1/24
```

```bash
sudo install -o root -g systemd-network -m 0640 /etc/wireguard/wg0.key /etc/systemd/network/wg0.key
sudo systemctl restart systemd-networkd
```

On a server peer, add `Endpoint=203.0.113.10:51820` and `PersistentKeepalive=25` to its `[WireGuardPeer]`, and `Address=10.66.0.11/32` to its `.network`. networkd adds routes for `AllowedIPs` only with `RouteTable=main` in `[WireGuard]` (systemd 250 and later) or an explicit `[Route]` section with `Destination=10.66.0.1/32`.

### 5. Install the hub on the WireGuard address

Bring `wg0` up first, then:

```bash
sudo kodeblue-hub/install-hub.sh --self-signed --listen 10.66.0.1:8443 --public-url https://10.66.0.1:8443
```

This runs `kodeblue-hub serve --self-signed --listen 10.66.0.1:8443 --public-url https://10.66.0.1:8443`. The self-signed certificate includes `10.66.0.1`, and the install commands the console prints use that address.

Servers are peers too. To keep a compromised server from reaching the console, limit it to the operators' tunnel addresses; servers can still sync:

```bash
sudo kodeblue-hub/install-hub.sh --self-signed --listen 10.66.0.1:8443 --public-url https://10.66.0.1:8443 \
  --console-allow 10.66.0.100/32
```

The hub cannot bind `10.66.0.1` before `wg0` has it. Order the hub after the tunnel with a drop-in (`sudo systemctl edit kodeblue-hub`):

```ini
[Unit]
Wants=wg-quick@wg0.service
After=wg-quick@wg0.service
```

With systemd-networkd, use `systemd-networkd-wait-online@wg0.service` in both lines if your systemd ships that unit. Either way, the hub unit has `Restart=always` with `RestartSec=5`, so it also recovers on its own once the address exists.

### 6. Firewall on the hub

Allow WireGuard, allow the hub port only on `wg0`, drop it everywhere else. Linux accepts a packet for `10.66.0.1` on any interface, so this rule matters even though the hub binds only that address.

nftables:

```
table inet kodeblue_hub
delete table inet kodeblue_hub

table inet kodeblue_hub {
	chain input {
		type filter hook input priority filter; policy accept;
		iifname != "wg0" tcp dport 8443 drop
	}
}
```

ufw:

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 51820/udp                      # or: from 198.51.100.0/24 to any port 51820 proto udp
sudo ufw allow in on wg0 to any port 8443 proto tcp
sudo ufw enable
```

WireGuard drops packets that are not from a configured peer key, so leaving UDP 51820 open to roaming laptops is reasonable.

### 7. Enroll over the tunnel

Sign in at `https://10.66.0.1:8443` from a laptop peer. **Add server** prints a command that already uses the WireGuard address and the pin:

```bash
f=$(mktemp) && { curl -fsSL --proto =https --proto-redir =https -k --pinnedpubkey sha256//… -o "$f" https://10.66.0.1:8443/install.sh && echo "<sha256>  $f" | sha256sum -c - && sudo sh "$f" --hub https://10.66.0.1:8443 --pin sha256//… --token kbe_…; s=$?; rm -f "$f"; (exit "$s"); }
```

Run it on a server whose tunnel is up. Each server still reaches its model endpoint directly, outside the tunnel, unless you route that through a private network too.

### Tailscale or Headscale

Tailscale gives the same result with less setup: install it on the hub, servers and laptops, run the hub with `--listen <hub tailnet IP>:8443 --public-url https://<hub tailnet IP>:8443 --self-signed`, and use ACLs so only servers and operators reach port 8443. Headscale is a self-hosted control server for the Tailscale clients, if you do not want a third-party coordination service. The ordering and firewall advice above applies the same way (`tailscaled.service` instead of `wg-quick@wg0`).

## TLS and pinning

- **A certificate from a public CA** (directly, at the proxy, or Cloudflare's behind a tunnel): servers verify it like any HTTPS client. No pin needed, and none should be set when the certificate's key changes on renewal.
- **A private CA**: give servers the CA certificate with `--ca-file` (installer and `kodeblue enroll`), stored as `[hub] ca_file`. Use `curl --cacert` to fetch `install.sh`.
- **Self-signed**: servers pin the public key (`[hub] pin`). This is full man-in-the-middle protection without a CA. The certificate is valid for 10 years and the key is reused across restarts.

Only a self-signed hub puts a pin in the install commands it prints, and `kodeblue-hub pin` on its own prints the self-signed certificate's pin. A `--tls-cert` hub is verified through its CA; to pin it anyway, print its pin with `kodeblue-hub pin --tls-cert <cert>` and add `--pin` to the install command yourself (and mind renewals, below).

A pin is a hash of the public key, not the certificate. Renewing a certificate with the **same key** keeps pins valid; a new key breaks them. Do not pin a certificate whose key changes on renewal (certbot creates a new key on each renewal unless you use `--reuse-key`).

### Renewing a `--tls-cert` certificate

The hub reads its certificate at start. After a renewal, copy the files and restart. A certbot deploy hook, `/etc/letsencrypt/renewal-hooks/deploy/kodeblue-hub`:

```sh
#!/bin/sh
install -o root -g kodeblue-hub -m 0640 /etc/letsencrypt/live/hub.example.com/fullchain.pem /etc/kodeblue-hub/tls.crt
install -o root -g kodeblue-hub -m 0640 /etc/letsencrypt/live/hub.example.com/privkey.pem /etc/kodeblue-hub/tls.key
systemctl restart kodeblue-hub
```

Servers lose their long-poll for a moment and reconnect.

### Rotating the self-signed key

Do this if `key.pem` may have leaked, or before the certificate expires. Servers accept exactly one pin and the hub cannot push a new one, so every server needs a local change:

```bash
# on the hub
sudo systemctl stop kodeblue-hub
sudo mv /var/lib/kodeblue-hub/tls /var/lib/kodeblue-hub/tls.old
sudo systemctl start kodeblue-hub
sudo -u kodeblue-hub kodeblue-hub pin --data /var/lib/kodeblue-hub     # the new pin

# on each server
sudo sed -i 's|^pin = .*|pin = "sha256//NEW…"|' /etc/kodeblue/kodeblue.toml
sudo systemctl restart kodeblue
```

Until a server has the new pin, its syncs fail and its notifications wait in the local outbox. The `sed` edits the first `pin = ` line, which is the one in `[hub]` unless you added others. Delete `tls.old` once all servers are back.

## Operator accounts

- **One account per person.** The audit log records who signed in, sent a message, approved containment or changed settings.
- **Strong passwords.** The minimum is 12 characters. Use a generated passphrase from a password manager. Passwords are stored as PBKDF2-SHA256 with 600,000 iterations.
- **Add, reset, remove** on the hub host:

  ```bash
  sudo -u kodeblue-hub kodeblue-hub user add alice --data /var/lib/kodeblue-hub   # also resets a password and signs alice out everywhere
  sudo -u kodeblue-hub kodeblue-hub user del alice --data /var/lib/kodeblue-hub   # her sessions end with the account
  sudo -u kodeblue-hub kodeblue-hub user list --data /var/lib/kodeblue-hub        # with last sign-in
  ```

- **Sessions** last 12 hours from sign-in, then the operator signs in again. The lifetime is fixed. **Sign out** ends the session on the hub.
- **Throttling.** After 8 failed sign-ins from one address within 15 minutes (an IPv6 /64 counts as one address), that address is refused until the window passes. After 24 failed sign-ins for one user name from any addresses, that name is refused for the rest of the window, except from browsers that user signed in from before: a successful sign-in sets a signed device cookie (HttpOnly, 180 days, key in the hub database) that exempts it from the per-user limit. That stops guessing spread over many addresses without letting anyone lock an operator out of their usual browser. A new browser can still be locked out for 15 minutes, another reason for `--console-allow`. Each attempt is counted before its password check, so concurrent attempts cannot overrun the limits. Password checks run a few at a time (half the CPUs, plus one slot reserved for known browsers); when all are busy a sign-in waits up to 2 seconds and then gets `503 Retry-After`, so a sign-in flood costs bounded CPU and the hub keeps serving servers. The counters are in memory and reset when the hub restarts. Behind a proxy, the address comes from `X-Forwarded-For`, which the hub believes only from `--trusted-proxy` addresses (default loopback), so a client cannot dodge the throttle by sending its own header. Set `--trusted-proxy` correctly (Docker: the bridge subnet), or all clients share the proxy's address and one throttle. `--console-allow` removes the sign-in form for everyone outside the list.
- **No second factor and no roles.** Every operator can do everything in the console. Limit it with `--console-allow`, a private network, or your own authenticating proxy.
- **Audit log** (console, **Audit**): sign-ins and failed sign-ins, servers added, renamed, revoked or deleted, enrollments and failed enrollments, new install tokens, every message, every approval or denial, case moves, and changes to model connections, agent settings, Slack and fleet settings. It is kept for a year. The console shows the latest 300 entries.

## Per server

### Response mode

Start every server in `recommend` (the default). Agents then request containment and a human approves it, on the server (`kodeblue respond approve <id>`) or in the console. Move to `contain` only after you have seen what the agents ask for on that server, and consider narrowing `allowed_actions` when you do.

`/etc/kodeblue/kodeblue.toml`:

```toml
[response]
mode = "recommend"
allowed_actions = ["kill_process", "quarantine_file", "block_ip", "disable_ssh_key", "lock_user", "stop_unit"]
protected_users = ["root", "deploy", "alice"]
protected_ips = ["192.0.2.0/28", "203.0.113.10"]
protected_units = ["ssh", "sshd", "kodeblue", "systemd-*", "dbus", "networking", "docker", "containerd", "postgresql", "nginx"]
max_actions_per_hour = 10
```

- `protected_users`: accounts that `lock_user` refuses and whose keys `disable_ssh_key` never touches. Root, uid 0 accounts, sudo/wheel/admin members and `kodeblue` are always treated the same way. A key planted for one of them is reported and recommended to a human. Keys in the learned baseline can never be disabled by an agent.
- `protected_ips`: addresses `block_ip` refuses: your office, VPN egress, bastion, monitoring, and the hub. Loopback and link-local addresses are always refused.
- `refuse_private_ips`: by default a private address (RFC 1918, ULA) may be blocked when it is only a client of this server, such as an attacker on the internal network or in another container. The helper still refuses this server's own addresses, its default gateway, the resolvers in `/etc/resolv.conf`, any peer the server has a connection out to (database, hub, APIs) and any address with a live SSH session. Set `refuse_private_ips = true` to refuse every private address.
- `protected_units`: units `stop_unit` refuses (globs allowed). Add your databases and the services that keep the server reachable.
- In the console you can also mark actions **needs approval**, **automatic** or **off**. Those rules can only tighten this policy.

The containment helper re-reads this file for every request and refuses to run if the file is writable by anyone but root. It runs as root only per request, started by `kodeblue-respond.socket`, which only the `kodeblue` group can connect to. It does not follow symlinks that other users control, and it keeps its backups (quarantined files, disabled SSH key files) under the root-owned `/var/lib/kodeblue-respond/` (beside, not inside, the kodeblue-owned state dir, so the kodeblue user cannot replace it). On hosts without systemd, kodeblue falls back to `sudo -n`, which needs a sudoers rule; prefer systemd.

### What the hub may do: `[hub]`

| Setting (default) | When `true` | Set it `false` when |
|---|---|---|
| `accept_messages` (true) | operators can message the agents (investigate, tune monitors and allow rules, request containment) | you do not want remote instructions reaching this server |
| `share_transcripts` (true) | the agents' reasoning and tool output are visible on the hub | tool output from this server (file contents, logs, process lists) must not be stored on the hub |
| `accept_approvals` (true) | operators can approve or deny requested containment | approvals must happen on the server itself |
| `accept_settings` (true) | the server applies the console's model connections, per-agent models, instructions and approval rules | the hub must not be able to change which endpoint this server's data is sent to |
| `accept_learning` (true) | operators can run the learner or relearn the baseline (each run is announced in Slack) | a hub operator must not be able to make this server absorb its current state as normal |
| `messages_per_hour` (20) | rate limit on operator messages | |

The safest hub-connected server sets all five to `false`. It still reports incidents, findings, reports and its other records to the hub.

### Slack the hub cannot suppress

With a hub, the hub posts to Slack. A fully compromised hub could therefore hide notifications. For important servers, also post directly from the server:

```toml
[notify]
direct = true
slack_webhook_file = "/etc/kodeblue/slack.webhook"   # root:kodeblue 0640
```

### File permissions

The installer sets these. Check them after manual edits:

```bash
sudo stat -c '%U:%G %a %n' /etc/kodeblue /etc/kodeblue/* /var/lib/kodeblue /var/lib/kodeblue-respond /var/lib/kodeblue/hub-settings.json
```

| Path | Expected |
|---|---|
| `/etc/kodeblue` | `root:kodeblue 750` |
| `/etc/kodeblue/kodeblue.toml`, `inference.key`, `hub.key`, `slack.webhook` | `root:kodeblue 640` |
| `/var/lib/kodeblue` | `kodeblue:kodeblue 750` |
| `/var/lib/kodeblue-respond` | `root:kodeblue 750` (root helper state: action journal, quarantined files, `ssh-keys/` backups; beside the kodeblue-owned state dir so the kodeblue user cannot replace it) |
| `/var/lib/kodeblue/hub-settings.json` (model connections and keys from the hub) | `kodeblue 600` |

Do not add people to the `kodeblue` group. Members can read the server's hub key and model key.

### Budget

```toml
[budget]
daily_usd = 1.00                 # past this only critical findings reach a model; hard stop at 2x
input_usd_per_mtok = 0.10        # set both if your endpoint does not report cost per call
output_usd_per_mtok = 0.40
max_concurrent_incidents = 2
max_incidents_per_hour = 6
incident_max_iterations = 30
```

Without a reported cost or these prices, calls count as $0 and the daily budget is not enforced; kodeblue logs a warning. Operator conversations count against the same budget. Also set a spend limit at the provider (below).

### What data leaves the server

| Destination | What | How to keep it in |
|---|---|---|
| model endpoint | finding details and evidence, the server profile, and in agent sessions the output of read-only tools: file contents (secret paths are refused), log lines, process and network lists, package data | use a self-hosted OpenAI-compatible endpoint on your network (vLLM, Ollama, LiteLLM), and set `accept_settings = false` so the hub cannot repoint the server; or run without a model |
| hub | status, incidents, findings, monitors, allow rules, journal, containment actions and requests, reports, skills, definitions, notifications; agent transcripts unless `share_transcripts = false` | `share_transcripts = false`, or no hub |
| Slack | notification text (escaped, links disabled) | do not configure Slack |

## Model keys

- **Where they live.** Model connection keys are stored in the hub database (`hub.db`, mode 0600 in a 0700 directory) and are never shown back in the console. A server receives only the connections its agent roles use, with their keys, and keeps them in `/var/lib/kodeblue/hub-settings.json` (0600). The fleet's default key is written to `/etc/kodeblue/inference.key` at enrollment. A server's own key, if you set one, stays in `/etc/kodeblue/inference.key`.
- **Every server that uses a connection holds its key.** A compromised server exposes the keys of the connections its roles use.
- **Least privilege.** Create a dedicated key for kodeblue at the provider, limited to inference (no admin, billing or fine-tuning scope) and, where the provider allows it, to the models you picked.
- **Limits.** Set a monthly spend limit and, where available, an expiry on each key at the provider. kodeblue's own budget is a second line, not a substitute.
- **Separate keys per risk.** Use different connections (and keys) for groups of servers with different exposure, and pick models per server in its **Settings** tab, so one leaked key does not cover the fleet.
- **A key stays with its endpoint.** The console never shows a stored key, and it never moves one to another endpoint: changing a connection's scheme, host or port needs the key pasted again. The audit log records every URL change.
- **What the hub calls.** The hub calls model endpoints itself only to test a connection and list models, and posts to the Slack webhook. All of these go through the same guard. It refuses loopback, link-local and cloud-metadata addresses unless `--endpoint-allow` lists them ([hub.md](hub.md#connection-and-security-model)), so an operator cannot point it at the hub host's own services or the cloud metadata service. Leave `--endpoint-allow` unset unless a model gateway runs on the hub host.
- **Rotate.** Create the new key at the provider, paste it into the connection in **Settings**, and revoke the old key once servers have synced (the server's **Settings** tab shows whether it applied the change). Servers with `accept_settings = false` keep their own key: replace `/etc/kodeblue/inference.key` and run `sudo systemctl restart kodeblue`. Rotate the fleet default with `kodeblue-hub fleet set inference-key` (value on stdin).

## Keeping kodeblue itself healthy

### Updates

Watch the repository's releases and security advisories ([SECURITY.md](../SECURITY.md)): only the latest release receives fixes. Upgrade the hub first, then the servers ([deploy.md](deploy.md#upgrades)). Servers do not upgrade themselves; the hub shows each server's version, so you can spot ones left behind.

The install command the console prints pins the sha256 of the hub's `install.sh`, and that script pins the sha256 of each agent tarball, both taken when the hub first needs them after a start. So release files replaced under a running hub, or swapped in transit, fail the check, even together with a matching `SHA256SUMS`. All of it still comes from the hub: a hub compromised before it started, or its console, can print any command. Build releases yourself, from a commit you reviewed, and compare them with a release's `SHA256SUMS` (see [deploy.md](deploy.md)).

### Monitoring

- **Self-integrity.** kodeblue hashes its own binaries (`/usr/local/bin/kodeblue`, `/usr/local/lib/kodeblue/engine`) and its config on every sweep. A change outside an upgrade's maintenance window is a finding.
- **Coming back up.** The unit (`deploy/kodeblue.service`) brings kodeblue back from whatever takes it down, with no limit on the number of restarts (`StartLimitIntervalSec=0`): a crash, a kill or the OOM killer (`Restart=always`, 5 seconds later), and a hang. kodeblue pings the systemd watchdog (`WatchdogSec=2min`) only while its main loop keeps sweeping; when the loop misses its deadline (10 minutes past its next sweep, longer while a triage batch or the learner runs), it journals `watchdog.stalled`, systemd sends `SIGABRT` (every goroutine's stack goes to `journalctl -u kodeblue`) and starts it again. `OOMScoreAdjust=-900` makes it one of the last processes the kernel kills when memory runs out, and starting kodeblue also starts its containment socket. It starts at boot. A deliberate `systemctl stop` is not undone: see *Stopped for good*.
- **Stuck sensors.** A sensor whose read does not return within 60 seconds (hung storage, a dead network filesystem, a watched path made to block) is left behind: the sweep, the other sensors and the monitors keep running, and that sensor is skipped until its read returns, when the next sweep uses its late result. A sensor stuck for 5 minutes raises a `kodeblue.sensor_stuck` finding, because it is blind until then.
- **Monitoring gaps.** kodeblue writes a heartbeat. If it was not running for 10 minutes or more, it raises a finding on the next start ("kodeblue was not running for …").
- **Stopped for good.** A gap finding needs kodeblue to start again. To notice a server whose kodeblue stays down, watch it from outside: the console's **Servers** view marks a server offline after 2 minutes without a sync, but the hub does not post that to Slack. Add an external check, for example `systemctl is-active kodeblue` from your existing monitoring, or alert on the hub's `GET /healthz` and on servers going offline.
- **Logs.** `journalctl -u kodeblue` on servers, `journalctl -u kodeblue-hub` on the hub. Failed syncs log `hub sync failed` with the retry delay.
- **Spend.** `sudo kodeblue status` shows spend against the budget; the console's Overview shows it per server.
- **Planned work.** Open a maintenance window (`sudo kodeblue maintenance 2h "reason"`) before changing a server. Every window is journaled and posted to Slack, because anyone with root can open one. An unexpected window is itself a signal.
