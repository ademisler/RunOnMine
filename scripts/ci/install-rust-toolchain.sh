#!/usr/bin/env bash
set -euo pipefail
toolchain="${1:?toolchain required}"
components="${2:-}"
targets="${3:-}"
args=(toolchain install "$toolchain" --profile minimal --no-self-update)
if [[ -n "$components" ]]; then
  IFS=',' read -ra component_list <<< "$components"
  for component in "${component_list[@]}"; do
    [[ -n "$component" ]] && args+=(--component "$component")
  done
fi
rustup "${args[@]}"
rustup default "$toolchain"
if [[ -n "$targets" ]]; then
  IFS=',' read -ra target_list <<< "$targets"
  for target in "${target_list[@]}"; do
    [[ -n "$target" ]] && rustup target add --toolchain "$toolchain" "$target"
  done
fi
rustc --version --verbose
cargo --version
