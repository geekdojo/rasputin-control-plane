# identity-on-mac.Dockerfile — the container scripts/identity-on-mac.sh runs
# the console stack test in (geekdojo/geekdojo-brain#989): Ubuntu with
# systemd as PID 1, Ubuntu's docker CLI (it drives the host's docker through
# the mounted socket), the Go toolchain scripts/vuln-scan.sh pins and Node 22.
# It is built for the Mac's own architecture; Keycloak's x64 JRE runs in a
# linux/amd64 container beside it (RASPUTIN_CONSOLE_KC_PLATFORM).
#
# Every download is checked against a hash written here: Go's from go.dev's
# published sha256, Node's from nodejs.org's SHASUMS256.txt. A bump changes a
# version and its hashes together.
FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus docker.io ca-certificates curl jq unzip xz-utils util-linux procps rsync \
 && rm -rf /var/lib/apt/lists/*

# The Go toolchain equal to scripts/vuln-scan.sh's GOTOOLCHAIN.
ARG GO_VERSION=1.26.6
ARG GO_SHA256_ARM64=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e
ARG GO_SHA256_AMD64=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
RUN case "$TARGETARCH" in arm64) sum="$GO_SHA256_ARM64";; amd64) sum="$GO_SHA256_AMD64";; *) echo "unsupported $TARGETARCH" >&2; exit 1;; esac \
 && curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" \
 && echo "${sum}  /tmp/go.tgz" | sha256sum -c - \
 && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz

# Node 22, as CI's setup-node gives the frontend and theme builds.
ARG NODE_VERSION=22.23.3
ARG NODE_SHA256_ARM64=a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f
ARG NODE_SHA256_AMD64=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
RUN case "$TARGETARCH" in arm64) a=arm64; sum="$NODE_SHA256_ARM64";; amd64) a=x64; sum="$NODE_SHA256_AMD64";; *) exit 1;; esac \
 && curl -fsSL -o /tmp/node.txz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${a}.tar.xz" \
 && echo "${sum}  /tmp/node.txz" | sha256sum -c - \
 && tar -C /usr/local --strip-components=1 -xJf /tmp/node.txz && rm /tmp/node.txz

ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    GOTOOLCHAIN=local

# systemd as PID 1; it must not start the image's own docker daemon.
RUN systemctl mask docker.service docker.socket containerd.service
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
