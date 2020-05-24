acme-redirect(1)

# NAME

acme-redirect - Tiny http daemon that answers acme challenges and redirects
everything else to https

# SYNOPSIS

*acme-redirect* \
[-v|--verbose] \
[-c /etc/acme-redirect.conf] \
[--config-dir /etc/acme-redirect.d] \
[--acme-email <acme-email>] \
[--acme-url https://acme-v02.api.letsencrypt.org/directory] \
[--chall-dir /run/acme-redirect] \
[--data-dir /var/lib/acme-redirect] \
<subcommand>

# DESCRIPTION

acme-redirect is a tiny http server that implements the ACME (Automated
Certificate Management Environment) protocol and redirects everything else to
https. It can run directly on port 80 and supports automatic issuance and renew
of certificates out of the box with minimal configuration.

# DAEMON

Runs the http daemon.

*-B <bind-addr>, --bind-addr <bind-addr>*
	The address to listen on. Default is *[::]:80*.

*--chroot*
	Chroot into the challenge directory.

*--user <user>*
	Drop from root to this user.

*acme-redirect daemon*

# RENEW

Renew certificates that are about to expire and run the given commands to
trigger a certificate reload.

*-n, --dry-run*
	Do not actually do anything, just show what would happen.

*--force-renew*
	Renew certificates even if they are not about to expire.

*--skip-cleanup*
	Don't clean up old certs that are not live anymore.

*--skip-restarts*
	Do not execute the configured *exec* commands.

*<certs ...>*
	Only renew specific certs. If no certificate is selected explicitly, renew
	all certificates.

*acme-redirect renew*

# STATUS

Shows the certificates currently available and their expiry status.

*acme-redirect status*

# AUTOMATIC RENEW

You can simply run *acme-redirect renew* periodically. If you're using systemd
you can use the systemd timer with:

*systemctl enable --now acme-redirect-renew.timer*

# SEE ALSO

*acme-redirect.conf*(5), *acme-redirect.d*(5).

# AUTHORS

acme-redirect was originally written by kpcyrd and is hosted at
https://github.com/kpcyrd/acme-redirect
