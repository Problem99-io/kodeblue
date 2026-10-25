# kodeblue hub image. Released images: ghcr.io/problem99-io/kodeblue-hub
# (:latest and :vX.Y.Z for stable releases, :nightly). Build from the repository root:
#   docker build -f deploy/hub/Dockerfile -t kodeblue-hub .
# Run behind a TLS-terminating proxy (Caddy, nginx, Traefik) on the same host:
#   docker run -v kodeblue-hub:/data -p 127.0.0.1:8080:8080 \
#     -e KODEBLUE_HUB_PUBLIC_URL=https://hub.example.com -e KODEBLUE_HUB_BEHIND_PROXY=1 -e KODEBLUE_HUB_LISTEN=:8080 \
#     -e KODEBLUE_HUB_TRUSTED_PROXIES=172.16.0.0/12 kodeblue-hub     (the proxy reaches the container via the Docker bridge)
# or with its own self-signed certificate:
#   docker run -v kodeblue-hub:/data -p 8443:8443 -e KODEBLUE_HUB_PUBLIC_URL=https://hub.example.com:8443 -e KODEBLUE_HUB_SELF_SIGNED=1 kodeblue-hub
# First operator:  docker exec -it <container> kodeblue-hub user add admin
# The build stages run on the build host and cross-compile, so a multi-arch
# build (--platform linux/amd64,linux/arm64) needs no emulated Go compiler.
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_DATE_EPOCH
ARG ARCHES="amd64 arm64"
# The agent release the hub serves to servers (both architectures).
RUN VERSION=$VERSION COMMIT=$COMMIT SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ARCHES="$ARCHES" sh deploy/build-dist.sh /out
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/Problem99-io/kodeblue/internal/blue/hubproto.Version=$VERSION" \
      -o /out/kodeblue-hub ./cmd/kodeblue-hub

FROM alpine:3.22
ARG VERSION=dev
LABEL org.opencontainers.image.title="kodeblue-hub" \
      org.opencontainers.image.description="kodeblue hub: one console for a fleet of kodeblue servers" \
      org.opencontainers.image.source="https://github.com/Problem99-io/kodeblue" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$VERSION"
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 kodeblue-hub && mkdir -p /data && chown kodeblue-hub /data
COPY --from=build /out/kodeblue-hub /usr/local/bin/kodeblue-hub
COPY --from=build /out/agent /opt/kodeblue-hub/dist
COPY LICENSE NOTICE /usr/share/doc/kodeblue-hub/
ENV KODEBLUE_HUB_DATA=/data KODEBLUE_HUB_DIST=/opt/kodeblue-hub/dist KODEBLUE_HUB_LISTEN=:8443
USER kodeblue-hub
VOLUME /data
EXPOSE 8443 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- --no-check-certificate http://127.0.0.1:8080/healthz >/dev/null 2>&1 || wget -qO- --no-check-certificate https://127.0.0.1:8443/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["kodeblue-hub"]
CMD ["serve"]
