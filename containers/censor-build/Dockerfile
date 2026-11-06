# Builds wl-censor for the wire container with nDPI (LGPL-3.0) linked in
# statically, without anything installed on the host but Docker:
#
#   wirelab censor build
#
# which builds this image and copies /wl-censor out of it into
# containers/wire/bin (no BuildKit needed).
#
# nDPI is pinned to 5.0: from 6.0 its TLS, QUIC and DNS dissectors are under
# ntop's dual licence (README.license.md in nDPI). The source of both, and
# this file, are what LGPL-3.0 section 4 asks for to relink.
FROM golang:1.26-alpine AS build
RUN apk add --no-cache build-base autoconf automake libtool pkgconf git bash linux-headers
ARG NDPI_REF=5.0
RUN git clone --depth 1 --branch "$NDPI_REF" https://github.com/ntop/nDPI.git /src/nDPI \
    && cd /src/nDPI \
    && ./autogen.sh \
    && ./configure --with-only-libndpi --prefix=/usr \
    && make -j"$(nproc)" \
    && make install \
    && git rev-parse HEAD > /ndpi-commit
WORKDIR /src/censor
COPY . .
ENV CGO_ENABLED=1 GOFLAGS=-trimpath
# The censor's own tests, then nDPI against nDPI's test captures: QUIC
# Initials decrypted, the tunnels recognised.
ENV NDPI_TESTS=/src/nDPI/tests/cfgs/default/pcap
RUN go test -tags ndpi -v -run 'NDPI' ./... && go test -tags ndpi ./... \
    && go build -tags ndpi -ldflags='-s -w -linkmode external -extldflags "-static"' -o /out/wl-censor . \
    && cp /ndpi-commit /out/wl-censor.ndpi-commit

FROM scratch AS out
COPY --from=build /out/ /
