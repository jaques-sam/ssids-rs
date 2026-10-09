#!/usr/bin/env bash
# Single source of truth for CI; run locally before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."

# Crates that must stay free of native-only code so the UI can ship as WebAssembly.
WASM_CRATES=(ssids-domain ssids-app)

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

wasm_args=()
for crate in "${WASM_CRATES[@]}"; do wasm_args+=(-p "$crate"); done
cargo clippy --target wasm32-unknown-unknown "${wasm_args[@]}" -- -D warnings
