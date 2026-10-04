# UniTether — top-level build & test entry points

PY      ?= python3
NODE    ?= node
CARGO   ?= cargo
MANIFEST := host/Cargo.toml

.PHONY: all test conformance e2e bench rust rust-test android gui gui-build i18n clean

all: rust

test: conformance e2e i18n rust-test gui-build

conformance:
	$(PY) tests/protocol/test_vectors.py
	$(PY) tests/protocol/test_state.py
	$(PY) tests/protocol/test_v11.py
	$(PY) tests/protocol/test_v11_vectors.py
	$(PY) tests/protocol/test_limits.py
	$(PY) tests/protocol/test_scheduler.py
	$(PY) tests/protocol/test_obs.py
	$(PY) tests/protocol/test_session_manager.py
	$(PY) tests/protocol/test_file.py
	$(PY) tests/protocol/test_security.py
	$(PY) tests/protocol/fuzz.py --iters 500
	$(PY) tests/e2e/test_resume.py
	$(PY) tests/e2e/test_chaos.py
	$(NODE) tests/node/test.mjs

e2e:
	bash tests/e2e/run_e2e.sh

i18n:
	$(PY) tests/i18n/check_i18n.py
	$(PY) tests/i18n/check_gui_i18n.py

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

# Frontend compile gate (fast; no Rust/Tauri toolchain needed)
gui-build:
	cd host/gui && npm install --no-audit --no-fund && npx vite build

clean:
	$(CARGO) clean --manifest-path $(MANIFEST)
	rm -rf host/gui/dist host/gui/node_modules
