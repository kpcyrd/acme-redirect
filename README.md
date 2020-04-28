# acme-redirect(1)

A minimal http daemon that redirects


This sovles the chicken-egg problem of the certificate being necessary to start nginx, and nginx to complete the acme challenge for the certificate.


# Development

```
cargo run -- --config contrib/confs/acme-redirect.conf --config-dir target/ --chall-dir . daemon -B '[::]:8080' -v
```
