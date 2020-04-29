# acme-redirect(1)

A minimal http daemon that redirects


This sovles the chicken-egg problem of the certificate being necessary to start nginx, and nginx to complete the acme challenge for the certificate.


# Development

```
mkdir tmp
export ACME_CONFIG="$PWD/contrib/confs/acme-redirect.conf"
export ACME_CONFIG_DIR="$PWD/contrib/confs/certs.d/"
export ACME_CHALL_DIR="$PWD/tmp/"
export ACME_DATA_DIR="$PWD/tmp/"

cargo run -- status
cargo run -- daemon -B '[::]:8080' -v
```
