#!/bin/sh
# kodeblue installer — one kodeblue per server, running as its own user.
#
# One server, no hub (downloads the latest release from GitHub and checks it
# against the release's SHA256SUMS; asks for the model's API key):
#   curl -fsSL https://github.com/Problem99-io/kodeblue/releases/latest/download/install.sh | sudo sh -s -- --inference-url https://openrouter.ai/api --model <model>
# From a kodeblue hub (the command the hub's "Add server" dialog prints):
#   curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --hub https://hub.example.com --token kbe_…
# From an unpacked release directory (offline):
#   sudo ./deploy/install.sh [--hub URL --token kbe_…]
# Upgrade a server that is already enrolled (downloads with its own hub key):
#   curl -fsSL https://hub.example.com/install.sh | sudo sh -s -- --hub https://hub.example.com
#
# Options:
#   --hub URL              kodeblue hub to connect to (https://…)
#   --token T              one-time enrollment token from the hub (single use, expires).
#                          Prefer $KODEBLUE_ENROLL_TOKEN or --token-file: a token on
#                          the command line is visible in the process list.
#   --token-file F         read the enrollment token from file F (or - for stdin)
#   --pin sha256//…        hub certificate pin, when the hub uses a self-signed certificate
#   --ca-file F            CA certificate that signed the hub's certificate
#   --name NAME            server name in its config (default: hostname; the hub shows the name given in "Add server")
#   --mode M               containment policy for a NEW install: off | recommend (default) | contain
#   --hub-max-mode M       the highest mode the hub may switch this server to: recommend | contain
#                          ([response] hub_max_mode; contain lets the hub turn on actions without
#                          approval). Applied to an existing config too.
#   --inference-url URL    OpenAI-compatible model endpoint (otherwise: hub default, or a prompt)
#   --model M              model for triage and agents (with --inference-url)
#   --inference-key-file F file holding the endpoint's API key (otherwise: hub default, or a prompt)
#   --slack-webhook-file F Slack incoming-webhook URL, only for servers WITHOUT a hub (with a hub, Slack is set on the hub)
#   --telegram-bot-token-file F Telegram bot token (standalone servers; set on the hub otherwise)
#   --telegram-chat-id-file F   Telegram destination chat ID or @channelusername
#   --no-start             install and enroll, but do not start the services
#   --uninstall [--purge]  remove kodeblue (--purge also deletes its config and state)
#
# Without --hub, KODEBLUE_RELEASE_URL picks another release to download from
# (default https://github.com/Problem99-io/kodeblue/releases/latest/download;
# e.g. …/releases/download/v0.2.0 for one version). Pass it through sudo:
#   curl -fsSL … | sudo KODEBLUE_RELEASE_URL=… sh -s -- …
#:usage-end
set -eu

# usage prints the header comment above, from line 2 to the :usage-end marker,
# so it never drifts when the comment grows. The leading "# " is stripped.
usage() {
  if [ -f "$0" ] && [ "${0##*/}" = install.sh ]; then
    sed -n '2,/^#:usage-end/ { /^#:usage-end/d; s/^# \{0,1\}//; p; }' "$0"
  else
    echo "kodeblue installer; options: https://github.com/Problem99-io/kodeblue/blob/main/deploy/install.sh"
  fi
}

# The token may arrive in the environment (preferred: never on a command line).
HUB="" TOKEN="${KODEBLUE_ENROLL_TOKEN:-}" PIN="" CA="" NAME="" MODE="" HUBMAXMODE="" INFURL="" INFMODEL="" KEYFILE="" SLACKFILE="" TELEGRAMTOKENFILE="" TELEGRAMCHATFILE="" START=1 UNINSTALL=0 PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --hub) HUB=${2%/}; shift 2 ;;
    --token) TOKEN=$2; shift 2 ;;
    --token-file)
      if [ "$2" = - ]; then TOKEN=$(cat); else TOKEN=$(cat "$2"); fi
      TOKEN=$(printf '%s' "$TOKEN" | tr -d '\r\n'); shift 2 ;;
    --pin) PIN=$2; shift 2 ;;
    --ca-file) CA=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    --mode) MODE=$2; shift 2 ;;
    --hub-max-mode) HUBMAXMODE=$2; shift 2 ;;
    --inference-url) INFURL=$2; shift 2 ;;
    --model) INFMODEL=$2; shift 2 ;;
    --inference-key-file|--im-key-file) KEYFILE=$2; shift 2 ;;
    --slack-webhook-file) SLACKFILE=$2; shift 2 ;;
    --telegram-bot-token-file) TELEGRAMTOKENFILE=$2; shift 2 ;;
    --telegram-chat-id-file) TELEGRAMCHATFILE=$2; shift 2 ;;
    --no-start) START=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "kodeblue install: unknown option $1" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "kodeblue runs on Linux"
case "$MODE" in ""|off|recommend|contain) ;; *) die "--mode must be off, recommend or contain" ;; esac
case "$HUBMAXMODE" in ""|off|recommend|contain) ;; *) die "--hub-max-mode must be off, recommend or contain" ;; esac
HAVE_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then HAVE_SYSTEMD=1; fi

if [ "$UNINSTALL" = 1 ]; then
  say "removing kodeblue"
  if [ "$HAVE_SYSTEMD" = 1 ]; then
    systemctl disable --now kodeblue.service kodeblue-respond.socket 2>/dev/null || true
    rm -f /etc/systemd/system/kodeblue.service /etc/systemd/system/kodeblue-respond.socket /etc/systemd/system/kodeblue-respond@.service
    systemctl daemon-reload
  fi
  rm -f /usr/local/bin/kodeblue
  rm -rf /usr/local/lib/kodeblue
  if [ "$PURGE" = 1 ]; then
    rm -rf /etc/kodeblue /var/lib/kodeblue /var/lib/kodeblue-respond
    userdel kodeblue 2>/dev/null || true
    say "kodeblue, its config and its state were removed"
  else
    say "binaries and units removed; config in /etc/kodeblue and state in /var/lib/kodeblue kept (--purge removes them)"
  fi
  exit 0
fi

# Only a script file named install.sh is in a release directory. Piped in
# (curl … | sudo sh), $0 is the shell and the current directory, which anyone
# may have filled, must never be taken for a release.
here=/nonexistent root=/nonexistent
if [ -f "$0" ] && [ "${0##*/}" = install.sh ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  root=$(cd "$here/.." && pwd)
fi
# loopback_http: a plain-HTTP URL to this host itself, nothing else
# (http://localhost:@evil.example is evil.example to curl).
loopback_http() {
  case "$1" in *@*) return 1 ;; esac
  case "$1" in
    http://localhost|http://localhost/*|http://localhost:[0-9]*|http://127.0.0.1|http://127.0.0.1/*|http://127.0.0.1:[0-9]*) return 0 ;;
  esac
  return 1
}

# ---- bootstrap: fetch the release (from the hub, or GitHub) when not run from one ----
if [ ! -f "$root/kodeblue" ] || [ ! -f "$root/kodeblue-engine" ] || [ ! -f "$here/kodeblue.service" ]; then
  # The release just unpacked re-runs this script: it must not download again
  # (a noexec /tmp would loop forever).
  [ -z "${KODEBLUE_UNPACKED:-}" ] || die "the downloaded release is incomplete ($root)"
  if [ -z "$HUB" ]; then
    [ -z "$TOKEN" ] || die "--token needs --hub"
    { [ -z "$PIN" ] && [ -z "$CA" ]; } || die "--pin and --ca-file need --hub"
  fi
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m) (amd64 and arm64 are built)" ;;
  esac
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM
  if [ -z "$HUB" ]; then
    REL=${KODEBLUE_RELEASE_URL:-https://github.com/Problem99-io/kodeblue/releases/latest/download}
    REL=${REL%/}
    # Only HTTPS, redirects included (GitHub redirects downloads to its CDN).
    case "$REL" in
      https://*) PROTO=https ;;
      *) loopback_http "$REL" && PROTO=http || die "KODEBLUE_RELEASE_URL must be an https:// URL" ;;
    esac
    say "downloading kodeblue ($ARCH) from $REL"
    curl -fsSL --proto "=$PROTO" --proto-redir "=$PROTO" --retry 3 -o "$tmp/kodeblue.tgz" "$REL/kodeblue-linux-$ARCH.tar.gz" || die "download of kodeblue-linux-$ARCH.tar.gz failed"
    curl -fsSL --proto "=$PROTO" --proto-redir "=$PROTO" --retry 3 -o "$tmp/SHA256SUMS" "$REL/SHA256SUMS" || die "download of SHA256SUMS failed"
  else
    # curl may use only the hub URL's own protocol, redirects included, so a
    # proxy cannot downgrade the download (and its credential) to plain HTTP.
    case "$HUB" in
      https://*) PROTO=https ;;
      *) loopback_http "$HUB" && PROTO=http || die "--hub must be an https:// URL" ;;
    esac
    AUTH=$TOKEN
    if [ -z "$AUTH" ] && [ -s /etc/kodeblue/hub.key ]; then AUTH=$(cat /etc/kodeblue/hub.key); fi
    [ -n "$AUTH" ] || die "pass --token (from the hub's Add server dialog) to download kodeblue"
    # The credential goes in a header file, never on curl's command line.
    printf 'Authorization: Bearer %s\n' "$AUTH" > "$tmp/auth.h"
    chmod 600 "$tmp/auth.h"
    fetch() {
      if [ -n "$PIN" ]; then
        curl -fsSL --proto "=$PROTO" --proto-redir "=$PROTO" --retry 3 -k --pinnedpubkey "$PIN" -H @"$tmp/auth.h" -o "$2" "$HUB/dist/$1"
      elif [ -n "$CA" ]; then
        curl -fsSL --proto "=$PROTO" --proto-redir "=$PROTO" --retry 3 --cacert "$CA" -H @"$tmp/auth.h" -o "$2" "$HUB/dist/$1"
      else
        curl -fsSL --proto "=$PROTO" --proto-redir "=$PROTO" --retry 3 -H @"$tmp/auth.h" -o "$2" "$HUB/dist/$1"
      fi
    }
    say "downloading kodeblue ($ARCH) from $HUB"
    fetch "kodeblue-linux-$ARCH.tar.gz" "$tmp/kodeblue.tgz" || die "download failed (expired token? wrong pin?)"
    if [ -n "${KODEBLUE_DIST_SHA256SUMS:-}" ]; then
      # Pinned into this script by the hub that served it, so a tarball swapped
      # together with the SHA256SUMS beside it still fails the check.
      printf '%s\n' "$KODEBLUE_DIST_SHA256SUMS" > "$tmp/SHA256SUMS"
    else
      fetch SHA256SUMS "$tmp/SHA256SUMS" || die "download of SHA256SUMS failed"
    fi
    rm -f "$tmp/auth.h"
  fi
  want=$(grep " kodeblue-linux-$ARCH.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
  got=$(sha256sum "$tmp/kodeblue.tgz" | cut -d' ' -f1)
  { [ -n "$want" ] && [ "$want" = "$got" ]; } || die "checksum mismatch for kodeblue-linux-$ARCH.tar.gz"
  tar -xzf "$tmp/kodeblue.tgz" -C "$tmp"
  set --
  [ -n "$HUB" ] && set -- "$@" --hub "$HUB"
  # The token is handed to the unpacked installer in the environment, never on
  # its command line (the process list is world-readable).
  [ -n "$PIN" ] && set -- "$@" --pin "$PIN"
  [ -n "$CA" ] && set -- "$@" --ca-file "$CA"
  [ -n "$NAME" ] && set -- "$@" --name "$NAME"
  [ -n "$MODE" ] && set -- "$@" --mode "$MODE"
  [ -n "$HUBMAXMODE" ] && set -- "$@" --hub-max-mode "$HUBMAXMODE"
  [ -n "$INFURL" ] && set -- "$@" --inference-url "$INFURL"
  [ -n "$INFMODEL" ] && set -- "$@" --model "$INFMODEL"
  [ -n "$KEYFILE" ] && set -- "$@" --inference-key-file "$KEYFILE"
  [ -n "$SLACKFILE" ] && set -- "$@" --slack-webhook-file "$SLACKFILE"
  [ -n "$TELEGRAMTOKENFILE" ] && set -- "$@" --telegram-bot-token-file "$TELEGRAMTOKENFILE"
  [ -n "$TELEGRAMCHATFILE" ] && set -- "$@" --telegram-chat-id-file "$TELEGRAMCHATFILE"
  [ "$START" = 0 ] && set -- "$@" --no-start
  KODEBLUE_UNPACKED=1 KODEBLUE_ENROLL_TOKEN=$TOKEN sh "$tmp/kodeblue/deploy/install.sh" "$@"
  exit $?
fi

# ---- install from this release directory ----
v=$("$root/kodeblue" version 2>/dev/null | cut -d' ' -f2) || v=""   # empty on a noexec mount
say "installing kodeblue${v:+ $v}"
if ! id kodeblue >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/kodeblue --shell /usr/sbin/nologin --user-group kodeblue
fi
for g in adm systemd-journal; do
  if getent group "$g" >/dev/null; then usermod -aG "$g" kodeblue || true; fi
done

UPGRADE=0
if [ -x /usr/local/bin/kodeblue ]; then
  UPGRADE=1
  # kodeblue watches its own binaries: declare the upgrade as planned work so
  # the swap is absorbed (and journaled) instead of raising a tamper alert.
  # Only when kodeblue has run here: otherwise there is no baseline to protect,
  # and a root-run CLI would create the database as root.
  if [ -f /etc/kodeblue/kodeblue.toml ] && [ -f /var/lib/kodeblue/kodeblue.db ]; then
    from=$(/usr/local/bin/kodeblue version 2>/dev/null | cut -d' ' -f2)
    to=$("$root/kodeblue" version 2>/dev/null | cut -d' ' -f2)
    /usr/local/bin/kodeblue maintenance 10m "kodeblue upgrade $from -> $to by install.sh (binaries /usr/local/bin/kodeblue, /usr/local/lib/kodeblue/engine will change)" --config /etc/kodeblue/kodeblue.toml >/dev/null 2>&1 || true
    chown kodeblue:kodeblue /var/lib/kodeblue/maintenance-until 2>/dev/null || true
  fi
fi
install -m 0755 "$root/kodeblue" /usr/local/bin/kodeblue.new || die "could not install /usr/local/bin/kodeblue"
mv -f /usr/local/bin/kodeblue.new /usr/local/bin/kodeblue
install -d -m 0755 /usr/local/lib/kodeblue
install -m 0755 "$root/kodeblue-engine" /usr/local/lib/kodeblue/engine.new || die "could not install /usr/local/lib/kodeblue/engine"
mv -f /usr/local/lib/kodeblue/engine.new /usr/local/lib/kodeblue/engine
rm -f /usr/local/lib/kodeblue/kodecode   # the engine's name in early releases

install -d -o root -g kodeblue -m 0750 /etc/kodeblue
if [ ! -f /etc/kodeblue/kodeblue.toml ]; then
  install -o root -g kodeblue -m 0640 "$here/kodeblue.toml.example" /etc/kodeblue/kodeblue.toml
  if [ -n "$MODE" ]; then sed -i "s/^mode = \"recommend\"/mode = \"$MODE\"/" /etc/kodeblue/kodeblue.toml; fi
  if [ -n "$NAME" ]; then
    esc=$(printf '%s' "$NAME" | sed 's/[\\"]/\\&/g; s/[&|]/\\&/g')
    sed -i "s|^name = \"web-1\".*|name = \"$esc\"|" /etc/kodeblue/kodeblue.toml
  else
    sed -i 's|^name = "web-1".*|# name = "web-1"                # defaults to the hostname|' /etc/kodeblue/kodeblue.toml
  fi
elif [ -n "$MODE" ]; then
  warn "existing /etc/kodeblue/kodeblue.toml kept; --mode not applied (edit [response] mode yourself)"
fi
if [ -n "$HUBMAXMODE" ]; then
  # Root's choice: how far the hub may raise [response] mode on this server.
  if grep -q '^hub_max_mode *=' /etc/kodeblue/kodeblue.toml; then
    sed -i "s/^hub_max_mode *=.*/hub_max_mode = \"$HUBMAXMODE\"/" /etc/kodeblue/kodeblue.toml
  elif grep -q '^\[response\]' /etc/kodeblue/kodeblue.toml; then
    sed -i "/^\[response\]/a hub_max_mode = \"$HUBMAXMODE\"" /etc/kodeblue/kodeblue.toml
  else
    printf '\n[response]\nhub_max_mode = "%s"\n' "$HUBMAXMODE" >> /etc/kodeblue/kodeblue.toml
  fi
  if [ "$HUBMAXMODE" = contain ]; then
    say "the hub may switch this server to contain (actions without approval): [response] hub_max_mode in /etc/kodeblue/kodeblue.toml"
  fi
fi
chown root:kodeblue /etc/kodeblue/kodeblue.toml && chmod 0640 /etc/kodeblue/kodeblue.toml
# Earlier releases named the model key im.key.
if [ -s /etc/kodeblue/im.key ] && [ ! -s /etc/kodeblue/inference.key ]; then
  mv -f /etc/kodeblue/im.key /etc/kodeblue/inference.key
  sed -i 's|/etc/kodeblue/im.key|/etc/kodeblue/inference.key|' /etc/kodeblue/kodeblue.toml
fi
for f in inference.key slack.webhook telegram.token telegram.chat hub.key; do
  [ -f "/etc/kodeblue/$f" ] || install -o root -g kodeblue -m 0640 /dev/null "/etc/kodeblue/$f"
done
install -d -o kodeblue -g kodeblue -m 0750 /var/lib/kodeblue
# The database belongs to the kodeblue user, whoever touched it last.
for f in /var/lib/kodeblue/kodeblue.db /var/lib/kodeblue/kodeblue.db-wal /var/lib/kodeblue/kodeblue.db-shm; do
  [ -e "$f" ] && chown kodeblue:kodeblue "$f"
done
# The root helper's state (action journal, quarantined files, SSH key backups)
# lives beside /var/lib/kodeblue, not inside it: /var/lib/kodeblue is the
# kodeblue user's, so a compromised kodeblue could rename a directory within it
# and plant a forged journal that the root helper would act on. /var is root's.
install -d -o root -g kodeblue -m 0750 /var/lib/kodeblue-respond
# Migrate an older install's journal out of the kodeblue-owned directory.
if [ -d /var/lib/kodeblue/response ] && [ ! -e /var/lib/kodeblue-respond/actions.jsonl ]; then
  cp -a /var/lib/kodeblue/response/. /var/lib/kodeblue-respond/ 2>/dev/null || true
  chown -R root:kodeblue /var/lib/kodeblue-respond
  rm -rf /var/lib/kodeblue/response
fi

# ---- secrets (never echoed, never on a command line) ----
readsecret() { # prompt -> stdout; empty when there is no terminal
  # A subshell: dash (sh on Debian/Ubuntu) exits on a failed redirect of the
  # builtin ":", which killed non-interactive installs here.
  ( : > /dev/tty ) 2>/dev/null || return 0   # no usable terminal (e.g. curl | sh from CI)
  { printf '%s' "$1" > /dev/tty; } 2>/dev/null || return 0
  stty -echo < /dev/tty 2>/dev/null || true
  IFS= read -r v < /dev/tty || v=""
  stty echo < /dev/tty 2>/dev/null || true
  printf '\n' > /dev/tty
  printf '%s' "$v"
}
readline() { # prompt -> stdout (echoed); empty when there is no terminal
  ( : > /dev/tty ) 2>/dev/null || return 0
  { printf '%s' "$1" > /dev/tty; } 2>/dev/null || return 0
  IFS= read -r v < /dev/tty || v=""
  printf '%s' "$v"
}
putsecret() { # value file
  ( umask 027; printf '%s\n' "$1" > "$2.tmp" ) && chown root:kodeblue "$2.tmp" && chmod 0640 "$2.tmp" && mv -f "$2.tmp" "$2"
}
# Files given on the command line win; the hub's fleet defaults (handed over
# at enrollment) only fill what is still empty; a prompt comes last.
if [ -n "$KEYFILE" ] && [ ! -s /etc/kodeblue/inference.key ]; then putsecret "$(tr -d '\r\n' < "$KEYFILE")" /etc/kodeblue/inference.key; fi
if [ -n "$SLACKFILE" ] && [ ! -s /etc/kodeblue/slack.webhook ]; then putsecret "$(tr -d '\r\n' < "$SLACKFILE")" /etc/kodeblue/slack.webhook; fi

valid_telegram_token() { [ "$(printf %s "$1" | wc -l)" -eq 0 ] && printf %s "$1" | LC_ALL=C grep -Eq '^[0-9]+:[A-Za-z0-9_-]+$'; }
valid_telegram_chat() { [ "$(printf %s "$1" | wc -l)" -eq 0 ] && printf %s "$1" | LC_ALL=C grep -Eq '^(-?[1-9][0-9]*|@[A-Za-z][A-Za-z0-9_]{4,})$'; }

if [ -n "$TELEGRAMTOKENFILE" ] && [ ! -s /etc/kodeblue/telegram.token ]; then k=$(sed 's/\r$//' "$TELEGRAMTOKENFILE"); valid_telegram_token "$k" || die "Invalid Telegram token file"; putsecret "$k" /etc/kodeblue/telegram.token; fi
if [ -n "$TELEGRAMCHATFILE" ] && [ ! -s /etc/kodeblue/telegram.chat ]; then k=$(sed 's/\r$//' "$TELEGRAMCHATFILE"); valid_telegram_chat "$k" || die "Invalid Telegram chat file"; putsecret "$k" /etc/kodeblue/telegram.chat; fi

# ---- enroll with the hub ----
if [ -n "$TOKEN" ]; then
  [ -n "$HUB" ] || die "--token needs --hub"
  say "enrolling with $HUB"
  set -- --hub "$HUB"
  [ -n "$PIN" ] && set -- "$@" --pin "$PIN"
  [ -n "$CA" ] && set -- "$@" --ca-file "$CA"
  [ -n "$NAME" ] && set -- "$@" --name "$NAME"
  KODEBLUE_ENROLL_TOKEN=$TOKEN /usr/local/bin/kodeblue enroll --config /etc/kodeblue/kodeblue.toml "$@" || die "enrollment failed"
fi

# ---- model endpoint (flags > hub default from enrollment > prompt) ----
# The installer starts (or restarts) kodeblue itself, after the units are in place.
kb() { KODEBLUE_NO_RESTART=1 /usr/local/bin/kodeblue "$@" --config /etc/kodeblue/kodeblue.toml; }
if [ -n "$INFURL" ] || [ -n "$INFMODEL" ]; then
  kb inference --url "$INFURL" --model "$INFMODEL" >/dev/null || die "could not set the model endpoint"
elif [ ! -s /etc/kodeblue/hub.key ] && ! kb inference >/dev/null 2>&1 && ! grep -q '^base_url *= *"' /etc/kodeblue/kodeblue.toml; then
  # A server on a hub takes its model from the hub (Settings), never a prompt.
  u=$(readline "Model endpoint, any OpenAI-compatible base URL such as https://openrouter.ai/api (Enter to skip; the model layers stay off until it is set): ")
  if [ -n "$u" ]; then
    m=$(readline "Model name for triage and agents: ")
    if [ -n "$m" ]; then kb inference --url "$u" --model "$m" >/dev/null || warn "model endpoint not saved"; fi
  fi
fi
# A key only means something with the server's own endpoint.
if [ ! -s /etc/kodeblue/inference.key ] && grep -q '^base_url *= *"' /etc/kodeblue/kodeblue.toml; then
  k=$(readsecret "API key for the model endpoint (Enter to skip): ")
  if [ -n "$k" ]; then putsecret "$k" /etc/kodeblue/inference.key; fi
fi
if [ -s /etc/kodeblue/hub.key ]; then
  # On a hub, model keys belong on the hub: hand this server's key to it and
  # remove every copy here (the server then calls its models through the hub).
  kb move-keys || warn "model keys stay on this server for now; to move them later: sudo kodeblue move-keys"
fi
if [ -s /etc/kodeblue/hub.key ]; then
  # The hub (control center) owns Slack: this server queues notifications for it.
  [ -s /etc/kodeblue/slack.webhook ] && warn "/etc/kodeblue/slack.webhook is ignored while this server reports to a hub (Slack is configured on the hub; set [notify] direct = true to also post directly)"
elif [ ! -s /etc/kodeblue/slack.webhook ] && [ "$UPGRADE" = 0 ]; then
  k=$(readsecret "Slack incoming-webhook URL (optional, Enter to skip): ")
  if [ -n "$k" ]; then putsecret "$k" /etc/kodeblue/slack.webhook; fi
fi

if [ -s /etc/kodeblue/hub.key ]; then
  [ ! -s /etc/kodeblue/telegram.token ] || warn "Local Telegram settings are ignored while enrolled (configure Telegram on the hub; set [notify] direct = true to also post directly)"
elif [ "$UPGRADE" = 0 ]; then
  if [ ! -s /etc/kodeblue/telegram.token ]; then
    k=$(readsecret "Telegram bot token (optional, Enter to skip): ")
    if [ -n "$k" ]; then valid_telegram_token "$k" || die "Invalid Telegram token"; putsecret "$k" /etc/kodeblue/telegram.token; fi
  fi
  if [ -s /etc/kodeblue/telegram.token ] && [ ! -s /etc/kodeblue/telegram.chat ]; then
    k=$(readline "Telegram chat ID or @channelusername: ")
    if [ -n "$k" ]; then valid_telegram_chat "$k" || die "Invalid Telegram chat ID"; putsecret "$k" /etc/kodeblue/telegram.chat; fi
  fi
fi

# ---- services ----
if [ "$HAVE_SYSTEMD" = 1 ]; then
  install -m 0644 "$here/kodeblue.service" "$here/kodeblue-respond.socket" "$here/kodeblue-respond@.service" /etc/systemd/system/
  systemctl daemon-reload
  if [ "$START" = 1 ]; then
    systemctl --quiet enable --now kodeblue-respond.socket
    # Enabled = started at boot; the unit restarts it after a crash, a kill,
    # the OOM killer or a hang (watchdog).
    systemctl enable kodeblue.service >/dev/null 2>&1 || die "could not enable kodeblue.service, so it would not start at boot (systemctl enable kodeblue)"
    systemctl restart kodeblue.service
    say "kodeblue is running and restarts itself if it crashes, is killed or hangs"
  fi
else
  warn "systemd not found: services not installed. Run '/usr/local/bin/kodeblue run' as the kodeblue user under your supervisor."
fi

# A server on a hub takes its models from the hub's Settings, which arrive on
# its first sync after the start: give that a moment before saying none came.
models=0
if kb inference >/dev/null 2>&1; then
  models=1
elif [ -s /etc/kodeblue/hub.key ] && [ "$START" = 1 ] && [ "$HAVE_SYSTEMD" = 1 ]; then
  n=0
  while [ "$n" -lt 10 ]; do
    sleep 3
    if kb inference >/dev/null 2>&1; then models=1; break; fi
    n=$((n + 1))
  done
fi
if [ "$models" = 0 ]; then
  if [ -s /etc/kodeblue/hub.key ]; then
    warn "no model from the hub yet: sensors, detection and monitors run, and learning waits for a model. Add a model connection in the hub's Settings (or check this server shows as connected there); this server picks it up on its own."
  else
    warn "no model yet: sensors, detection and monitors run, and learning waits for a model. Set one with: sudo kodeblue inference --url https://… --model … --key-file -"
  fi
fi
if [ "$UPGRADE" = 1 ]; then
  say "upgraded. A 10-minute maintenance window absorbs the binary swap (journaled; visible on the hub)."
else
  say "done. kodeblue first learns this server (about 30 minutes), then watches it."
fi
if [ -s /etc/kodeblue/hub.key ]; then say "reporting to the hub at $(grep -m1 '^url = ' /etc/kodeblue/kodeblue.toml | cut -d'"' -f2)"; fi
say "status: sudo kodeblue status · logs: sudo journalctl -fu kodeblue · policy: /etc/kodeblue/kodeblue.toml ([response] mode)"
