# Maintainer: kpcyrd <kpcyrd[at]archlinux[dot]org>

pkgname=acme-redirect
pkgver=0.0.0
pkgrel=1
pkgdesc='TODO'
url='https://github.com/kpcyrd/acme-redirect'
arch=('x86_64')
license=('GPL3')
makedepends=('cargo' 'scdoc')
backup=('etc/acme-redirect.conf')

build() {
  cd ..
  cargo build --release --locked
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
  install -dm 755 "${pkgdir}/etc/acme-redirect.d"
  install -Dm 644 -t "${pkgdir}/etc" \
    contrib/confs/acme-redirect.conf

  # install systemd configs
  install -Dm 644 -t "${pkgdir}/usr/lib/systemd/system" \
    contrib/systemd/acme-redirect-renew.service \
    contrib/systemd/acme-redirect-renew.timer \
    contrib/systemd/acme-redirect.service
  install -Dm 644 contrib/systemd/acme-redirect.sysusers "${pkgdir}/usr/lib/sysusers.d/acme-redirect.conf"
  install -Dm 644 contrib/systemd/acme-redirect.tmpfiles "${pkgdir}/usr/lib/tmpfiles.d/acme-redirect.conf"
}

# vim: ts=2 sw=2 et:
