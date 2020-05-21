# acme-redirect(1)

A minimal http daemon that answers acme challenges and redirects everything
else to https.

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

Start the acme-redirect daemon:
```bash
systemctl enable --now acme-redirect
```

Request certificates:
```bash
acme-redirect renew
```

Setup automatic renew:
```bash
systemctl enable --now acme-redirect-renew.timer
```

Your certificate is located here:
```
/var/lib/acme-redirect/live/example.com/live/fullchain
/var/lib/acme-redirect/live/example.com/live/privkey
```

# Installation

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
echo deb https://apt.vulns.sexy $(lsb_release -cs) main >> /etc/apt/sources.list
apt update && apt install acme-redirect
```

## Build from source

```bash
git clone https://github.com/kpcyrd/acme-redirect.git
cd acme-redirect/
cargo build --release

install -Dm 755 -t /usr/local/bin \
    target/release/acme-redirect

install -Dm 644 contrib/confs/acme-redirect.conf -t /etc
install -Dm 644 contrib/confs/certs.d/example.com.conf /etc/acme-redirect.d/example.com.conf.sample

install -Dm 644 -t /etc/systemd/system \
    contrib/systemd/acme-redirect-renew.service \
    contrib/systemd/acme-redirect-renew.timer \
    contrib/systemd/acme-redirect.service
install -Dm 644 contrib/systemd/acme-redirect.sysusers /etc/sysusers.d/acme-redirect.conf
install -Dm 644 contrib/systemd/acme-redirect.tmpfiles /etc/tmpfiles.d/acme-redirect.conf

sudo systemd-sysusers
sudo systemd-tmpfiles --create
```

# Status

I'm using this in production since summer 2020.

# Development

```bash
mkdir tmp
export ACME_CONFIG="$PWD/contrib/confs/acme-redirect.conf"
export ACME_CONFIG_DIR="$PWD/contrib/confs/certs.d/"
export ACME_CHALL_DIR="$PWD/tmp/"
export ACME_DATA_DIR="$PWD/tmp/"

cargo run -- status
cargo run -- daemon -B '[::]:8080' -v
```

# License

GPLv3+
