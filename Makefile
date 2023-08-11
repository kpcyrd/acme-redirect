build:
	repro-env build -- sh -c ' \
	CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
	RUSTFLAGS="-C strip=symbols" \
	cargo build --target x86_64-unknown-linux-musl --release --locked --features vendored'

docs: contrib/docs/acme-redirect.1 contrib/docs/acme-redirect.d.5 contrib/docs/acme-redirect.conf.5

contrib/docs/%: contrib/docs/%.scd
	scdoc < $^ > $@

.PHONY: build docs
