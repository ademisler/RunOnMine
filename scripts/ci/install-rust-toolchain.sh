#!/usr/bin/env bash
set -euo pipefail
toolchain="${1:?toolchain required}"
components="${2:-}"
targets="${3:-}"
args=(toolchain install "$toolchain" --profile minimal --no-self-update)
IFS=',' read -ra component_list <<< "$components"
for component in "${component_list[@]}"; do
  [[ -n "$component" ]] && args+=(--component "$component")
done
rustup "${args[@]}"
rustup default "$toolchain"
IFS=',' read -ra target_list <<< "$targets"
for target in "${target_list[@]}"; do
  [[ -n "$target" ]] && rustup target add --toolchain "$toolchain" "$target"
done
rustc --version --verbose
cargo --version
