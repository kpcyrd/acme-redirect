#!/bin/sh
set -ex
docker build -t pkg-debian-acme-redirect-build contrib/debian/
docker run --rm \
    -v "$PWD:/src" \
    -w /src \
    pkg-debian-acme-redirect-build \
    cargo deb
docker run --rm \
    -v "$PWD:/src" \
    pkg-debian-acme-redirect-build \
    chown -vR "$(id -u):$(id -g)" /src/target
