FROM rust:alpine3.17
ENV RUSTFLAGS="-C target-feature=-crt-static"
WORKDIR /app
RUN apk add --no-cache musl-dev openssl-dev
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/acme-redirect .
RUN strip acme-redirect

FROM alpine:3.17
RUN apk add --no-cache libgcc openssl
COPY --from=0 /app/acme-redirect /usr/bin
ENTRYPOINT ["acme-redirect"]
