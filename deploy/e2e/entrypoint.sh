#!/bin/sh
# Bring up the "server", then kodeblue as its own user with read capabilities.
rm -f /run/rsyslogd.pid; rsyslogd 2>/dev/null
/usr/sbin/sshd
cron
nohup python3 /opt/shop/app.py >/dev/null 2>&1 &
# Mock Slack webhook (runs as nobody so kodeblue cannot write its log).
touch /var/log/slack-mock.jsonl && chown nobody /var/log/slack-mock.jsonl
setpriv --reuid=nobody --regid=nogroup --clear-groups python3 /usr/local/lib/slack_mock.py >/dev/null 2>&1 &
touch /var/log/auth.log
start_kodeblue() {
  setpriv --reuid=kodeblue --regid=kodeblue --init-groups \
    --inh-caps=+dac_read_search,+sys_ptrace --ambient-caps=+dac_read_search,+sys_ptrace \
    -- /usr/local/bin/kodeblue run --config /etc/kodeblue/kodeblue.toml >>/var/log/kodeblue.log 2>&1
}
if [ "${KODEBLUE_AUTOSTART:-1}" = 1 ]; then
  while :; do start_kodeblue; sleep 3; done &
fi
exec sleep infinity
