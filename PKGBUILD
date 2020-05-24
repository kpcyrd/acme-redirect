# Maintainer: kpcyrd <kpcyrd[at]archlinux[dot]org>

pkgname=acme-redirect
pkgver=0.0.0
pkgrel=1
pkgdesc='Tiny http daemon that answers acme challenges and redirects everything else to https'
url='https://github.com/kpcyrd/acme-redirect'
arch=('x86_64')
license=('GPL3')
depends=('openssl')
makedepends=('cargo' 'scdoc')
backup=('etc/acme-redirect.conf')

build() {
  cd ..
  cargo build --release --locked
  make docs
}

package() {
  cd ..

  install -Dm 755 -t "${pkgdir}/usr/bin" \
    target/release/acme-redirect

  # install completions
  install -d "${pkgdir}/usr/share/bash-completion/completions" \
             "${pkgdir}/usr/share/zsh/site-functions" \
             "${pkgdir}/usr/share/fish/vendor_completions.d"
  "${pkgdir}/usr/bin/acme-redirect" completions bash > "${pkgdir}/usr/share/bash-completion/completions/acme-redirect"
  "${pkgdir}/usr/bin/acme-redirect" completions zsh > "${pkgdir}/usr/share/zsh/site-functions/_acme-redirect"
  "${pkgdir}/usr/bin/acme-redirect" completions fish > "${pkgdir}/usr/share/fish/vendor_completions.d/acme-redirect.fish"

  # install configs
  install -Dm 644 contrib/confs/acme-redirect.conf -t "${pkgdir}/etc"
  install -Dm 644 contrib/confs/certs.d/example.com.conf "${pkgdir}/etc/acme-redirect.d/example.com.conf.sample"

  # install systemd configs
  install -Dm 644 -t "${pkgdir}/usr/lib/systemd/system" \
    contrib/systemd/acme-redirect-renew.service \
    contrib/systemd/acme-redirect-renew.timer \
    contrib/systemd/acme-redirect.service
  install -Dm 644 contrib/systemd/acme-redirect.sysusers "${pkgdir}/usr/lib/sysusers.d/acme-redirect.conf"
  install -Dm 644 contrib/systemd/acme-redirect.tmpfiles "${pkgdir}/usr/lib/tmpfiles.d/acme-redirect.conf"

  # install docs
  install -Dm 644 README.md -t "${pkgdir}/usr/share/doc/${pkgname}"
  install -Dm 644 -t "${pkgdir}/usr/share/man/man1" \
    contrib/docs/acme-redirect.1
  install -Dm 644 -t "${pkgdir}/usr/share/man/man5" \
    contrib/docs/acme-redirect.conf.5 \
    contrib/docs/acme-redirect.d.5
}

# vim: ts=2 sw=2 et:
