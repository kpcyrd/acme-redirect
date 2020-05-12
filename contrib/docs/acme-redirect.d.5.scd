acme-redirect.d(5)

# NAME

acme-redirect.d - *acme-redirect* certificate configuration

# SYNOPSIS

/etc/acme-redirect.d/\*.conf

# DESCRIPTION

These files configure the certificates that should be requested and renewed by
*acme-redirect*.

# OPTIONS

_name=_
	The name to identify this certificate. The certificate is not going to be
	valid for this name unless it's also listed in *dns_names*.

_dns_names=_
	The list of names this certificate should be valid for.

_exec=_
	The list of commands that should be executed. You can use this to trigger
	certificate reloads.

# EXAMPLE

```
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

# SEE ALSO

*acme-redirect*(1), *acme-redirect.conf*(5).

# AUTHORS

acme-redirect was originally written by kpcyrd and is hosted at
https://github.com/kpcyrd/acme-redirect
