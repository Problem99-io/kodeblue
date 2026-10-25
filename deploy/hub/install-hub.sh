#!/bin/sh
# Install the kodeblue hub from an unpacked kodeblue-hub-linux-<arch>.tar.gz.
#
#   sudo ./install-hub.sh --public-url https://hub.example.com --self-signed
#   sudo ./install-hub.sh --public-url https://hub.example.com --tls-cert /etc/ssl/hub.crt --tls-key /etc/ssl/hub.key
#   sudo ./install-hub.sh --public-url https://hub.example.com --behind-proxy --listen 127.0.0.1:8080
#
#   --public-url URL   how servers and browsers reach the hub (required)
#   --listen ADDR      listen address (default :8443; :443 works too)
#   --self-signed      generate a certificate; servers pin its public key (no CA or domain needed)
#   --tls-cert/--tls-key  use your own certificate
#   --behind-proxy     plain HTTP behind a reverse proxy that terminates TLS (Caddy, nginx, Traefik)
#   --trusted-proxy LIST  with --behind-proxy: proxy addresses/CIDRs whose X-Forwarded-For is believed (default loopback)
#   --console-allow LIST  only these addresses/CIDRs reach the console, e.g. 10.66.0.0/24,203.0.113.7
#   --http-listen ADDR    extra loopback console listener for an SSH tunnel, e.g. 127.0.0.1:8080
#   --admin NAME       first operator account to create (default: admin)
#
# Re-running keeps lines you added to /etc/kodeblue-hub/env yourself, and the
# --trusted-proxy, --console-allow and --http-listen values you do not pass again.
set -eu
PUBLIC="" LISTEN=":8443" SELF=0 CERT="" KEY="" PROXY=0 ADMIN="admin" TRUSTED="" ALLOW="" HTTPL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --public-url) PUBLIC=${2%/}; shift 2 ;;
    --listen) LISTEN=$2; shift 2 ;;
    --self-signed) SELF=1; shift ;;
    --tls-cert) CERT=$2; shift 2 ;;
    --tls-key) KEY=$2; shift 2 ;;
    --behind-proxy) PROXY=1; shift ;;
    --trusted-proxy) TRUSTED=$2; shift 2 ;;
    --console-allow) ALLOW=$2; shift 2 ;;
    --http-listen) HTTPL=$2; shift 2 ;;
    --admin) ADMIN=$2; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$PUBLIC" ] || die "--public-url is required (e.g. https://hub.example.com:8443)"
case "$PUBLIC" in https://*) ;; *) die "--public-url must be https://" ;; esac
[ "$SELF" = 1 ] || [ -n "$CERT" ] || [ "$PROXY" = 1 ] || die "choose --self-signed, --tls-cert/--tls-key, or --behind-proxy"
here=$(cd "$(dirname "$0")" && pwd)
[ -x "$here/kodeblue-hub" ] || die "run from the unpacked kodeblue-hub directory"

id kodeblue-hub >/dev/null 2>&1 || useradd --system --home-dir /var/lib/kodeblue-hub --shell /usr/sbin/nologin --user-group kodeblue-hub
install -m 0755 "$here/kodeblue-hub" /usr/local/bin/kodeblue-hub.new && mv -f /usr/local/bin/kodeblue-hub.new /usr/local/bin/kodeblue-hub
install -d -o kodeblue-hub -g kodeblue-hub -m 0700 /var/lib/kodeblue-hub
rm -rf /var/lib/kodeblue-hub/dist
cp -R "$here/dist" /var/lib/kodeblue-hub/dist
chown -R kodeblue-hub:kodeblue-hub /var/lib/kodeblue-hub
install -d -m 0750 -g kodeblue-hub /etc/kodeblue-hub
if [ -n "$CERT" ]; then
  install -o root -g kodeblue-hub -m 0640 "$CERT" /etc/kodeblue-hub/tls.crt
  install -o root -g kodeblue-hub -m 0640 "$KEY" /etc/kodeblue-hub/tls.key
fi
# --trusted-proxy, --console-allow and --http-listen replace the value only
# when given; otherwise an existing setting is kept.
keys='DATA|LISTEN|PUBLIC_URL|SELF_SIGNED|BEHIND_PROXY|TLS_CERT|TLS_KEY'
[ -n "$TRUSTED" ] && keys="$keys|TRUSTED_PROXIES"
[ -n "$ALLOW" ] && keys="$keys|CONSOLE_ALLOW"
[ -n "$HTTPL" ] && keys="$keys|HTTP_LISTEN"
managed="^KODEBLUE_HUB_($keys)="
kept=""
[ -f /etc/kodeblue-hub/env ] && kept=$(grep -Ev "$managed" /etc/kodeblue-hub/env || true)
{
  echo "KODEBLUE_HUB_DATA=/var/lib/kodeblue-hub"
  echo "KODEBLUE_HUB_LISTEN=$LISTEN"
  echo "KODEBLUE_HUB_PUBLIC_URL=$PUBLIC"
  [ "$SELF" = 1 ] && echo "KODEBLUE_HUB_SELF_SIGNED=1"
  [ "$PROXY" = 1 ] && echo "KODEBLUE_HUB_BEHIND_PROXY=1"
  [ -n "$CERT" ] && echo "KODEBLUE_HUB_TLS_CERT=/etc/kodeblue-hub/tls.crt" && echo "KODEBLUE_HUB_TLS_KEY=/etc/kodeblue-hub/tls.key"
  [ -n "$TRUSTED" ] && echo "KODEBLUE_HUB_TRUSTED_PROXIES=$TRUSTED"
  [ -n "$ALLOW" ] && echo "KODEBLUE_HUB_CONSOLE_ALLOW=$ALLOW"
  [ -n "$HTTPL" ] && echo "KODEBLUE_HUB_HTTP_LISTEN=$HTTPL"
  [ -n "$kept" ] && printf '%s\n' "$kept"
  true
} > /etc/kodeblue-hub/env.new
mv -f /etc/kodeblue-hub/env.new /etc/kodeblue-hub/env
chown root:kodeblue-hub /etc/kodeblue-hub/env && chmod 0640 /etc/kodeblue-hub/env
install -m 0644 "$here/kodeblue-hub.service" /etc/systemd/system/kodeblue-hub.service
systemctl daemon-reload

if [ -z "$(runuser -u kodeblue-hub -- /usr/local/bin/kodeblue-hub user list --data /var/lib/kodeblue-hub)" ]; then
  say "create the first operator account ($ADMIN)"
  runuser -u kodeblue-hub -- /usr/local/bin/kodeblue-hub user add "$ADMIN" --data /var/lib/kodeblue-hub < /dev/tty
fi
systemctl enable kodeblue-hub >/dev/null 2>&1
systemctl restart kodeblue-hub
sleep 1
say "hub running at $PUBLIC (journalctl -fu kodeblue-hub)"
if [ "$SELF" = 1 ]; then
  for _ in 1 2 3 4 5; do [ -f /var/lib/kodeblue-hub/tls/cert.pem ] && break; sleep 1; done
  say "self-signed certificate pin (servers use it; browsers will warn once): $(runuser -u kodeblue-hub -- /usr/local/bin/kodeblue-hub pin --data /var/lib/kodeblue-hub)"
fi
say "optional fleet settings (value on stdin; inference-* set the default model connection; add more in the console, the hub posts to Slack itself):"
for k in inference-url inference-model inference-key slack-webhook; do
  echo "    runuser -u kodeblue-hub -- kodeblue-hub fleet set $k --data /var/lib/kodeblue-hub"
done
