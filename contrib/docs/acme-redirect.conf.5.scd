acme-redirect.conf(5)

# NAME

acme-redirect.conf - *acme-redirect* configuration files

# SYNOPSIS

/etc/acme-redirect.conf

# DESCRIPTION

This file configures general settings for *acme-redirect*. To configure
certificates have a look at *acme-redirect.d*(5).

# OPTIONS ([acme])

_acme_email=_
	The contact email for your acme provider to reach out to you. They are
	usually going to notify you if your automatic renew doesn't seem to be
	working, or if the acme protocol is going to be updated.

_acme_url=_
	The acme endpoint to use. The default is LetsEncrypt production.

_renew_if_days_left=_
	Renew the certificate if the number of days is *equal or lower*. You are
	going to run into issues if you set it lower than 1. The default is 30.

# OPTIONS ([system])

_exec=_
	A list of global fallback hooks that are executed if the certificate
	config didn't specify any hooks. The hooks are expected to be shell
	commands.

_exec_extra=_
	A list of global hooks that are executed after any certificate is renewed and
	its hooks have been executed. The hooks are expected to be shell commands.

# EXAMPLE

```
[acme]
acme_email = "nobody@example.com"
acme_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
renew_if_days_left = 30

[system]
## Default hooks if the certificate config doesn't define any
exec = [
    "systemctl reload nginx",
]
## Execute these hooks globally for all certificates
exec_extra = [
    "systemctl reload dovecot",
]
```

# SEE ALSO

*acme-redirect*(1), *acme-redirect.d*(5).

# AUTHORS

acme-redirect was originally written by kpcyrd and is hosted at
https://github.com/kpcyrd/acme-redirect
