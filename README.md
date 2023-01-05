# acme-redirect(1)

A tiny http daemon that answers acme challenges and redirects everything else
to https.

A minimal configuration looks like this:
```toml
# cat /etc/acme-redirect.d/example.com.conf
[cert]
name = "example.com"
dns_names = [
    "example.com",
    "www.example.com",
]
exec = [
    "systemctl reload nginx",
]
```

You don't need to edit anything else. Start the acme-redirect daemon:
```bash
systemctl enable --now acme-redirect
```

Ensure the service is running correctly and the redirect works as expected.
Ensure your A and AAAA records point to the right server and check everything
is working correctly by fetching a random proof from our local daemon.
```bash
acme-redirect check
```

If `OK` is displayed for every name you can request a real certificates:
```bash
acme-redirect renew
```

If this succeeded you should setup automatic renew:
```bash
systemctl enable --now acme-redirect-renew.timer
```

The certificate is located here:
```
/var/lib/acme-redirect/live/example.com/fullchain
/var/lib/acme-redirect/live/example.com/privkey
```

Example configuration looks like this:

## nginx
```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /var/lib/acme-redirect/live/example.com/fullchain;
    ssl_certificate_key /var/lib/acme-redirect/live/example.com/privkey;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;

    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /var/lib/acme-redirect/live/example.com/chain;
    resolver 127.0.0.1;

    # ...
}
```

## apache
```apache
<VirtualHost *:443>
    SSLEngine on

    SSLCertificateFile /var/lib/acme-redirect/live/example.com/fullchain
    SSLCertificateKeyFile /var/lib/acme-redirect/live/example.com/privkey

    Protocols h2 http/1.1
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>

SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder     off
SSLSessionTickets       off

SSLUseStapling On
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
```

## lighttpd
```
server.modules += ("mod_openssl")
$SERVER["socket"] == "0.0.0.0:443" {
    ssl.engine = "enable"
    ssl.privkey= "/var/lib/acme-redirect/live/example.com/privkey"
    ssl.pemfile= "/var/lib/acme-redirect/live/example.com/fullchain"
    ssl.openssl.ssl-conf-cmd = ("MinProtocol" => "TLSv1.2")
    #ssl.ca-file= "/var/lib/acme-redirect/live/example.com/chain" # (needed in $SERVER["socket"] before lighttpd 1.4.56 if ssl.pemfile in $HTTP["host"])
}
```

# Installation

<a href="https://repology.org/project/acme-redirect/versions"><img align="right" src="https://repology.org/badge/vertical-allrepos/acme-redirect.svg" alt="Packaging status"></a>

## Arch Linux

```bash
pacman -S acme-redirect
```

## Debian based

Currently supported: buster

```bash
apt install debian-keyring
gpg -a --export --keyring /usr/share/keyrings/debian-maintainers.gpg git@rxv.cc | apt-key add -
apt-key adv --keyserver keyserver.ubuntu.com --refresh-keys git@rxv.cc
echo deb https://apt.vulns.sexy stable main >> /etc/apt/sources.list.d/apt-vulns-sexy.list
apt update && apt install acme-redirect
```

## Build from source

```bash
git clone https://github.com/kpcyrd/acme-redirect.git
cd acme-redirect/

make build
```

### Install

```bash
sudo make install

sudo systemd-sysusers
sudo systemd-tmpfiles --create
```
### Uninstall

```bash
make uninstall
```

# Status

I'm using this in production since summer 2020 (northern hemisphere, around May).

# Development

```bash
mkdir -vp tmp/challs
export ACME_CONFIG="$PWD/contrib/confs/acme-redirect.conf"
export ACME_CONFIG_DIR="$PWD/contrib/confs/certs.d/"
export ACME_CHALL_DIR="$PWD/tmp/"
export ACME_DATA_DIR="$PWD/tmp/"

cargo run -- status
cargo run -- daemon -B '[::]:8080' -v
```

# boxxy

acme-redirect uses setuid and chroot to drop privileges before accepting
requests. This can be inspected with [boxxy][1].

```bash
mkdir -vp tmp/web
sudo chown root. tmp/web
cargo build --examples
(cd tmp/web && sudo ../../target/debug/examples/boxxy)
```

[1]: https://github.com/kpcyrd/boxxy-rs

# License

GPLv3+
