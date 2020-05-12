docs: contrib/docs/acme-redirect.1 contrib/docs/acme-redirect.d.5 contrib/docs/acme-redirect.conf.5

contrib/docs/%: contrib/docs/%.scd
	scdoc < $^ > $@

.PHONY: docs
