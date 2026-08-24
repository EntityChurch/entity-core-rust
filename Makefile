# Entity Core Rust — make + podman build convention.
#
# Host needs ONLY `make` + `podman` (no host Rust/cargo). The multistage
# Dockerfile carries the toolchain and compiles the release `entity` binary;
# the `toolchain` stage is reused for in-container tests.
IMAGE  := entity-core-rust
CARGO_CACHE := $(HOME)/.cache/cargo-entity-core-rust

# ----------------------------------------------------------------------------
# Source provenance stamped into the image (see the LABEL block in Dockerfile).
# A floating tag carries no identity, so a stale image is undetectable — which
# is exactly how a 2026-07-30 cross-impl run was served 36-hour-old code. These
# make the commit inside an image inspectable:
#     podman inspect --format '{{ index .Labels "org.entity.git.commit" }}' entity-core-rust
# A dirty tree stamps `<sha>-dirty` rather than claiming the bare commit.
# Kept separate from PODMAN_BUILD_CAPS so a caller injecting `--no-cache`
# through that variable (peer-manager does) composes rather than collides.
# ----------------------------------------------------------------------------
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
GIT_DIRTY  := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo true || echo false)
GIT_STAMP  := $(GIT_COMMIT)$(if $(filter true,$(GIT_DIRTY)),-dirty,)
PODMAN_BUILD_ARGS := --build-arg GIT_COMMIT=$(GIT_STAMP) --build-arg GIT_DIRTY=$(GIT_DIRTY)

# ============================================================================
# Podman resource caps — per-container ceilings so a build/run can't take the
# host down. Tune the COMMITTED defaults for THIS project; override per-machine
# WITHOUT editing this file via env vars or an untracked caps.local.mk.
#   Precedence (highest first):  env var  >  caps.local.mk  >  defaults below
#   CAP_SWAP == CAP_MEM  =>  zero swap: OOM-killed cleanly at the cap instead of
#   thrashing the host into a freeze.
# ============================================================================
-include caps.local.mk          # untracked per-machine overrides (gitignored)

# Defaults sized for this workspace: the heaviest target (`make test` — a clean
# `cargo test --release` compiling all crates + test binaries at -j12) peaks at
# ~2.5 GiB RSS; 4g is peak + ~60% headroom (protective without false-OOMing our
# own build). Re-measure if the workspace grows: container cgroup memory.peak.
CAP_MEM           ?= 4g         # hard memory ceiling per container
CAP_SWAP          ?= $(CAP_MEM) # keep == CAP_MEM (no swap); raise only deliberately
# `make godot` only. `godot 0.4`'s `codegen-full` is ONE rustc invocation that
# peaks at 4.44 GiB — more than every other crate in this workspace put together
# (2.12 GiB) — so it gets its own ceiling instead of forcing CAP_MEM to 8g for
# every `make test` on every machine. That asymmetry is exactly why
# `bindings/godot` is out of `default-members` and in this lane; see Cargo.toml.
GODOT_CAP_MEM     ?= 8g
CAP_PIDS          ?= 2048       # max procs/threads (RUN only) — stops fork bombs
CAP_CPUS          ?= 4          # CPU cores at runtime (RUN only; fractional ok)
CAP_CGROUP_PARENT ?=            # optional host slice to nest under, e.g. dev-heavy.slice

_cap_cgp := $(if $(strip $(CAP_CGROUP_PARENT)),--cgroup-parent=$(CAP_CGROUP_PARENT),)

# podman BUILD accepts --memory/--memory-swap/--cgroup-parent (NOT --cpus/--pids-limit)
PODMAN_BUILD_CAPS := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) $(_cap_cgp)
# podman RUN accepts the full set
PODMAN_RUN_CAPS   := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) \
                     --pids-limit=$(CAP_PIDS) --cpus=$(CAP_CPUS) $(_cap_cgp)

.PHONY: help build image toolchain test clippy lint fmt check clean wasm godot probe-webkit

.DEFAULT_GOAL := help

# ADR-0019 Tier-1 verbs: help build test lint fmt check clean (+ the repo's
# clippy/toolchain/wasm). lint is read-only (clippy + rustfmt --check); fmt
# writes (cargo fmt). Every recipe runs inside the pinned toolchain image.
help:
	@echo "entity-core-rust — make + podman (host needs only make + podman)"
	@echo
	@echo "  build    release build of the entity CLI in-container (alias: image)"
	@echo "  test     cargo test --release across the workspace"
	@echo "  lint     cargo clippy -D warnings + cargo fmt --check (read-only)"
	@echo "  fmt      cargo fmt (writes)"
	@echo "  check    lint + test + godot (the green gate)"
	@echo "  clean    remove the build + toolchain images"
	@echo "  clippy   clippy only · wasm   wasm32 cross-compile check"
	@echo "  godot    clippy + test bindings/godot + the sdk features only it enables"
	@echo "  probe-webkit  run a browser probe under WebKitGTK (PROBE=<file.html>)"

# Release build: compiles the `entity` CLI inside the container (Dockerfile
# builder stage) and produces the runtime image. Green on a bare box.
build:
	podman build $(PODMAN_BUILD_CAPS) $(PODMAN_BUILD_ARGS) -t $(IMAGE) .

# `image` alias keeps the older name working; `build` is the Tier-1 entry point.
image: build

# Toolchain-only image (rust + wasm32 target + clippy/rustfmt, no source).
toolchain:
	podman build $(PODMAN_BUILD_CAPS) --target toolchain -t $(IMAGE)-toolchain .

# In-container tests / lint against the bind-mounted source, with a persistent
# cargo registry cache so crates aren't re-fetched each run. CARGO_TARGET_DIR is
# redirected to a dedicated cache volume so cargo never writes into the repo's
# host-owned `target/` (the container runs as root; a host-uid-owned target/ from
# an earlier build would otherwise fail every write with Permission denied).
TARGET_CACHE := $(HOME)/.cache/cargo-target-entity-core-rust
define RUN_TOOLCHAIN
	mkdir -p $(CARGO_CACHE) $(TARGET_CACHE)
	podman run --rm $(PODMAN_RUN_CAPS) \
		-e CARGO_TARGET_DIR=/target \
		-v $(CURDIR):/work:Z \
		-v $(CARGO_CACHE):/usr/local/cargo/registry:Z \
		-v $(TARGET_CACHE):/target:Z \
		-w /work \
		$(IMAGE)-toolchain \
		sh -c '$(1)'
endef

# Same, with an explicit memory ceiling as $(1) — for the one lane whose peak is
# set by a dependency rather than by our own code (see GODOT_CAP_MEM).
define RUN_TOOLCHAIN_MEM
	mkdir -p $(CARGO_CACHE) $(TARGET_CACHE)
	podman run --rm --memory=$(1) --memory-swap=$(1) \
		--pids-limit=$(CAP_PIDS) --cpus=$(CAP_CPUS) $(_cap_cgp) \
		-e CARGO_TARGET_DIR=/target \
		-v $(CURDIR):/work:Z \
		-v $(CARGO_CACHE):/usr/local/cargo/registry:Z \
		-v $(TARGET_CACHE):/target:Z \
		-w /work \
		$(IMAGE)-toolchain \
		sh -c '$(2)'
endef

test: toolchain
	$(call RUN_TOOLCHAIN,cargo test --release)

clippy: toolchain
	$(call RUN_TOOLCHAIN,cargo clippy --all-targets -- -D warnings)

# Tier-1 lint = read-only static checks: clippy + rustfmt --check (absorbs the
# fmt-check that used to live under `fmt`, per ADR-0019).
lint: toolchain
	$(call RUN_TOOLCHAIN,cargo clippy --all-targets -- -D warnings && cargo fmt --check)

# Tier-1 fmt = autoformat (writes). Was `cargo fmt --check` (read-only) before
# ADR-0019 split the write-verb from the check; the --check now lives in lint.
fmt: toolchain
	$(call RUN_TOOLCHAIN,cargo fmt)

# ----------------------------------------------------------------------------
# bindings/godot — the one member outside `default-members` that a NATIVE lane
# has to cover
# ----------------------------------------------------------------------------
# `make test` / `make lint` run `default-members`, and `bindings/godot` is not in
# it: `godot 0.4`'s `codegen-full` is a single rustc peaking at 4.44 GiB, against
# 2.12 GiB for the whole rest of the workspace, so folding it in would force
# CAP_MEM to 8g for every `make test` everywhere. This lane is the trade — the
# same shape as `make wasm`, and stated at the Cargo.toml exclusion so the reason
# lives beside the exclusion rather than in a commit message.
#
# clippy AND test, because the default set gets both and a lane that only builds
# would silently drop the binding's lint coverage. Run it when you touch
# `core/*`, `bindings/sdk`, `bindings/shell` or the binding itself; `make check`
# runs it for you.
#
# `-p entity-sdk` rides along deliberately, and it is not padding. `entity-sdk`'s
# `identity` / `role` / `quorum` / `attestation` / `compute` features are off by
# default (wasm consumers pay for them in binary size) and `bindings/godot` is
# the only crate in the tree that turns them on. Selecting both packages puts
# them in ONE feature-unification group, so the sdk's test build gets those
# features and the **43 sdk tests gated behind them** run — measured: 216 in
# `make test`, 259 here. Drop the `-p entity-sdk` and those 43 are back to being
# reachable from no lane at all, which is the exact defect this whole
# arrangement exists to close.
godot: toolchain
	$(call RUN_TOOLCHAIN_MEM,$(GODOT_CAP_MEM),cargo clippy -p entity-core-godot --all-targets -- -D warnings && cargo test --release -p entity-core-godot -p entity-sdk)

# Tier-1 check = the green gate (lint + test + the godot lane).
check: lint test godot

# ----------------------------------------------------------------------------
# Per-feature gating sweep — the thing `test` and `clippy` structurally cannot
# see
# ----------------------------------------------------------------------------
# `cargo test`/`cargo clippy` over the workspace get CARGO'S FEATURE UNIFICATION:
# every feature any member enables is enabled for everyone. That is the right
# behaviour for the suite and it makes the suite BLIND to a mis-gated module —
# a `pub mod x;` missing the `#[cfg(feature = ...)]` its imports require builds
# fine, because something else in the workspace turned the feature on.
#
# A downstream consumer depending on `entity-peer` with `default-features =
# false` gets no such help, and that is exactly how it was found: `entity-peer`
# would not compile natively without `network` (network_link.rs), nor with
# `signaling` alone (a stray `network` gate on `carrier`), while `make test` sat
# at 1911·0F throughout. Reported by `entity-browser-rust`, whose build is that
# consumer.
#
# One feature at a time is the highest-signal check for this bug class: it
# isolates each gate against its own imports. Not in `check` — it is ~25 clippy
# runs — but run it when touching module gating, optional deps, or a `cfg`.
PEER_FEATURES := inbox network continuation subscription clock revision query history \
                 compute handlers conformance capability-handler attestation quorum \
                 identity role registry discovery relay signaling type-system content \
                 local-files websocket http-live
features: toolchain
	$(call RUN_TOOLCHAIN,set -e; \
	  echo "--- no-default-features ---"; \
	  cargo clippy -p entity-peer --no-default-features -- -D warnings; \
	  for f in $(PEER_FEATURES); do \
	    echo "--- $$f ---"; \
	    cargo clippy -p entity-peer --no-default-features --features $$f -- -D warnings; \
	  done; \
	  echo "--- all-features ---"; \
	  cargo clippy -p entity-peer --all-features -- -D warnings)

# Tier-1 clean = remove the build artifacts (the runtime + toolchain images).
clean:
	-podman rmi $(IMAGE) $(IMAGE)-toolchain

# wasm32 cross-compile check. Canonical feature set per CLAUDE.md (excludes
# websocket — tokio-tungstenite doesn't compile for wasm32-unknown-unknown).
# Builds the `entity-peer` crate (core/peer), which carries these features.
# NOTE: the feature list lives in a variable so its commas are not parsed as
# $(call) argument separators (which would silently truncate it at the first comma).
# `signaling` and `network` are in the wasm lane as of S1 (2026-08-02): both
# extension crates are socket-free by construction, so the carrier half — key
# derivation, the §6.1 coordination messages, candidate selection — is portable
# and CI now holds it that way. What is NOT in this build is the TCP wiring in
# core/peer (`punch_establisher`, `srflx`, `reuseport`), each already gated
# `not(target_arch = "wasm32")` with its reason in place. That gap is the
# browser leg's actual remaining work, not a portability defect.
#
# The three `bindings/wasm-worker-*` crates build in the same invocation as of
# 2026-08-10. They are the browser leg — wasm32-only at their lib root
# (`#![cfg(target_arch = "wasm32")]`), so a native `make test` compiles them to
# an empty module and can never see a break in them. AGENTS.md asked for them
# to be added by hand "when touching the worker crates", which is a convention
# nothing enforces: a change to core/peer or the SDK can break the worker
# stack, and whoever makes that change is precisely the person not thinking
# about workers. CI now holds them instead. They take no feature flags — the
# feature list applies to `entity-peer` alone.
WASM_FEATURES := inbox,continuation,subscription,clock,revision,query,history,compute,handlers,identity,role,registry,discovery,type-system,content,signaling,network
WASM_WORKER_CRATES := -p entity-wasm-worker-host -p entity-wasm-worker-proxy -p entity-wasm-worker-protocol
wasm: toolchain
	$(call RUN_TOOLCHAIN,cargo build --target wasm32-unknown-unknown -p entity-peer --no-default-features --features $(WASM_FEATURES) $(WASM_WORKER_CRATES))

# ----------------------------------------------------------------------------
# Browser probes — runtime facts a compile cannot establish
# ----------------------------------------------------------------------------
# WebKitGTK is `entity-browser-rust`'s Tauri desktop engine and was never
# measured; our RTC results are Firefox-only. Their AGENTS.md records the exact
# failure class ("green in Firefox/Selenium != works in WebKitGTK ... missing
# WorkerNavigator.storage bit us"), so this runs the probes against the engine
# that actually ships rather than the one that was convenient.
#
# Default probe is the load-bearing one: does WebRTC WORK here — construct, ICE,
# DTLS, and a delivered message — not merely "is the binding present". A missing
# channel transfer costs one main-thread hop; a missing RTCPeerConnection costs
# the whole substrate on that runtime.
PROBE ?= rtc-loopback-datachannel.html

probe-webkit:
	podman build $(PODMAN_BUILD_CAPS) -t $(IMAGE)-webkit-probe -f tools/browser-probes/Dockerfile.webkit tools/browser-probes
	podman run --rm $(PODMAN_RUN_CAPS) \
		-v $(CURDIR)/tools/browser-probes:/probes:ro,Z \
		$(IMAGE)-webkit-probe $(PROBE)
