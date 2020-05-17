FROM rust:alpine3.11
ENV RUSTFLAGS="-C target-feature=-crt-static"
WORKDIR /usr/src/acme-redirect
RUN apk add --no-cache musl-dev openssl-dev
COPY . .
RUN cargo build --release --locked
RUN strip target/release/acme-redirect

FROM alpine:3.11
RUN apk add --no-cache libgcc openssl
COPY --from=0 \
    /usr/src/acme-redirect/target/release/acme-redirect \
    /usr/local/bin/
ENTRYPOINT ["acme-redirect"]
