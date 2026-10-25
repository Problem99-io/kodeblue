#!/bin/sh
rm -f /run/rsyslogd.pid; rsyslogd 2>/dev/null
/usr/sbin/sshd
cron
nohup python3 /opt/shop/app.py >/dev/null 2>&1 &
touch /var/log/slack-mock.jsonl && chown nobody /var/log/slack-mock.jsonl
setpriv --reuid=nobody --regid=nogroup --clear-groups python3 /usr/local/lib/slack_mock.py >/dev/null 2>&1 &
touch /var/log/auth.log
(
  while [ ! -f /etc/kodeblue/.e2e-start ]; do sleep 2; done
  while :; do
    setpriv --reuid=kodeblue --regid=kodeblue --init-groups \
      --inh-caps=+dac_read_search,+sys_ptrace --ambient-caps=+dac_read_search,+sys_ptrace \
      -- /usr/local/bin/kodeblue run --config /etc/kodeblue/kodeblue.toml >>/var/log/kodeblue.log 2>&1
    sleep 3
  done
) &
exec sleep infinity
