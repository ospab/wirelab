FROM alpine:3
RUN apk add --no-cache iproute2 iproute2-tc tcpdump ethtool
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
