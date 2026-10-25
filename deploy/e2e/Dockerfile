# A disposable "production server" for kodeblue end-to-end tests: sshd, cron,
# sudo, rsyslog auth logs, an admin user and a small web app. kodeblue runs as
# its own unprivileged user with the same capabilities the systemd unit grants.
#   docker build -f deploy/e2e/Dockerfile -t kodeblue-e2e <dir with kodeblue, kodeblue-engine, deploy/>
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server cron sudo procps iproute2 iptables python3 netcat-openbsd curl ca-certificates rsyslog util-linux file \
 && rm -rf /var/lib/apt/lists/*
# The server's legitimate world.
RUN useradd -m -s /bin/bash -G sudo alice \
 && install -d -o alice -g alice -m 700 /home/alice/.ssh \
 && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeAliceKeyForE2eTestingOnly00000000000 alice@laptop" > /home/alice/.ssh/authorized_keys \
 && chown alice:alice /home/alice/.ssh/authorized_keys && chmod 600 /home/alice/.ssh/authorized_keys \
 && echo 'alice ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/alice && chmod 440 /etc/sudoers.d/alice \
 && mkdir -p /run/sshd /opt/shop \
 && printf '*/10 * * * * root /usr/bin/find /opt/shop -name "*.tmp" -mmin +60 -delete\n' > /etc/cron.d/shop-cleanup
COPY deploy/e2e/shop.py /opt/shop/app.py
COPY deploy/e2e/slack_mock.py /usr/local/lib/slack_mock.py
# kodeblue
RUN useradd --system --home-dir /var/lib/kodeblue --shell /usr/sbin/nologin --user-group kodeblue && usermod -aG adm kodeblue
COPY kodeblue /usr/local/bin/kodeblue
COPY kodeblue-engine /usr/local/lib/kodeblue/engine
RUN install -d -o root -g kodeblue -m 0750 /etc/kodeblue \
 && install -d -o kodeblue -g kodeblue -m 0750 /var/lib/kodeblue \
 && install -d -o root -g kodeblue -m 0750 /var/lib/kodeblue-respond \
 && echo 'kodeblue ALL=(root) NOPASSWD: /usr/local/bin/kodeblue respond exec --config /etc/kodeblue/kodeblue.toml' > /etc/sudoers.d/kodeblue \
 && chmod 440 /etc/sudoers.d/kodeblue
COPY deploy/e2e/kodeblue.toml /etc/kodeblue/kodeblue.toml
RUN chown root:kodeblue /etc/kodeblue/kodeblue.toml && chmod 640 /etc/kodeblue/kodeblue.toml \
 && echo "http://127.0.0.1:9999/hooks/test" > /etc/kodeblue/slack.webhook && chown root:kodeblue /etc/kodeblue/slack.webhook && chmod 640 /etc/kodeblue/slack.webhook
COPY deploy/e2e/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
