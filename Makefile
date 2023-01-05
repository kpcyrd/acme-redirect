prefix := $(or $(prefix),$(PREFIX),/usr/local)
bin_dir := $(prefix)/bin
share_dir := $(prefix)/share
man_dir := $(share_dir)/man
lib_dir := $(prefix)/lib
unit_dir := $(lib_dir)/systemd/system
sysusers_dir := $(lib_dir)/sysusers.d
tmpfiles_dir := $(lib_dir)/tmpfiles.d
conf_dir := /etc

# allow the binary path in unit files to be different to the intsall location
# this could be useful for packaging
unit_bin_path := $(bin_dir)/acme-redirect

# build
# ----------

.PHONY: build
build: build-bin build-comp docs

.PHONY: build-bin
build-bin:
	cargo build --release

.PHONY: build-comp
build-comp: build-bin comp/bash comp/zsh comp/fish

comp/%:
	mkdir -p comp
	target/release/acme-redirect completions $* > $@

.PHONY: docs
docs: contrib/docs/acme-redirect.1 contrib/docs/acme-redirect.d.5 contrib/docs/acme-redirect.conf.5

contrib/docs/%: contrib/docs/%.scd
	scdoc < $^ > $@

# install
# ----------

.PHONY: install
install: install-bin install-comp install-docs install-units install-conf

.PHONY: install-bin
install-bin: build-bin
	install -Dm 755 target/release/acme-redirect $(bin_dir)/acme-redirect

.PHONY: install-comp
install-comp: build-comp
	install -Dm 644 comp/bash $(share_dir)/bash-completion/completions/acme-redirect
	install -Dm 644 comp/zsh $(share_dir)/zsh/site-functions/_acme-redirect
	install -Dm 644 comp/fish $(share_dir)/fish/vendor_completions.d/acme-redirect.fish


.PHONY: install-docs
install-docs: docs
	install -d $(man_dir)/man1 $(man_dir)/man5
	install -Dm 644 -t $(man_dir)/man1 contrib/docs/acme-redirect.1
	install -Dm 644 -t $(man_dir)/man5 \
		contrib/docs/acme-redirect.conf.5 \
		contrib/docs/acme-redirect.d.5

.PHONY: install-units
install-units:
	# binary path needs to be updated
	for UNIT in acme-redirect.service acme-redirect-renew.service; do \
		cp contrib/systemd/$$UNIT contrib/systemd/$$UNIT.updated; \
		sed -i 's|/usr/bin/acme-redirect|$(unit_bin_path)|' contrib/systemd/$$UNIT.updated; \
		install -Dm 644 contrib/systemd/$$UNIT.updated $(unit_dir)/$$UNIT; \
	done

	install -Dm 644 -t $(unit_dir) contrib/systemd/acme-redirect-renew.timer

	install -Dm 644 contrib/systemd/acme-redirect.sysusers $(sysusers_dir)/acme-redirect.conf
	install -Dm 644 contrib/systemd/acme-redirect.tmpfiles $(tmpfiles_dir)/acme-redirect.conf

.PHONY: install-conf
install-conf:
	install -d $(conf_dir)
	install -Dm 644 -t $(conf_dir) contrib/confs/acme-redirect.conf
	install -Dm 644 contrib/confs/certs.d/example.com.conf \
		$(conf_dir)/acme-redirect.d/example.com.conf.sample
