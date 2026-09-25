# UniTether — top-level build & test entry points

PY      ?= python3
NODE    ?= node
CARGO   ?= cargo
MANIFEST := host/Cargo.toml

.PHONY: all test conformance e2e bench rust rust-test android gui clean

all: rust

test: conformance e2e rust-test

conformance:
	$(PY) tests/protocol/test_vectors.py
	$(NODE) tests/node/test.mjs

e2e:
	bash tests/e2e/run_e2e.sh

bench:
	$(PY) benchmarks/bench_loopback.py

rust:
	$(CARGO) build --release --manifest-path $(MANIFEST)

rust-test:
	$(CARGO) test --release --manifest-path $(MANIFEST)

android:
	cd device && ./gradlew assembleRelease

gui:
	cd host/gui && npm install && npx tauri build

clean:
	$(CARGO) clean --manifest-path $(MANIFEST)
	rm -rf host/gui/dist host/gui/node_modules
