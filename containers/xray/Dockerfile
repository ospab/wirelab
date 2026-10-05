FROM alpine:3
ARG XRAY_VERSION=v26.3.27
RUN apk add --no-cache curl unzip nginx openssl iproute2 coreutils ethtool
# The release's .dgst file comes from the same place as the archive, so this
# catches a broken download, not a compromised release.
RUN set -eu; cd /tmp; \
    base=https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION; \
    curl -fsSLo xray.zip "$base/Xray-linux-64.zip"; \
    curl -fsSLo xray.dgst "$base/Xray-linux-64.zip.dgst"; \
    want=$(awk '/^SHA2-256=/ { print $2 }' xray.dgst); \
    echo "$want  xray.zip" | sha256sum -c -; \
    unzip -q xray.zip xray -d /usr/local/bin; \
    rm xray.zip xray.dgst
COPY client.sh server.sh /
