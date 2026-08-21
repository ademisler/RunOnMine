#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "RunOnMine local voice setup is currently supported only on macOS." >&2
  exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
data_dir=${RUNONMINE_DATA_DIR:-"$HOME/Library/Application Support/dev.RunOnMine.RunOnMine"}
voice_dir="$data_dir/voice"
bin_dir="$voice_dir/bin"
model_dir="$voice_dir/models"
source_models=${RUNONMINE_VOICE_MODEL_SOURCE_DIR:-}
mkdir -p "$bin_dir" "$model_dir"
chmod 700 "$voice_dir" "$bin_dir" "$model_dir"

need_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_command swiftc
need_command curl
need_command shasum

if ! command -v whisper-cli >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    brew install whisper-cpp
  else
    echo "whisper-cli is required (install whisper.cpp)." >&2
    exit 1
  fi
fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    brew install ffmpeg
  else
    echo "ffmpeg is required." >&2
    exit 1
  fi
fi

if [ ! -x "$HOME/.local/bin/edge-tts" ] && command -v uv >/dev/null 2>&1; then
  uv tool install edge-tts
fi

swiftc -O "$root/packaging/macos/runonmine-record-audio.swift" -o "$bin_dir/runonmine-record-audio"
chmod 700 "$bin_dir/runonmine-record-audio"

install_model() {
  label=$1
  filename=$2
  url=$3
  expected=$4
  target="$model_dir/$filename"

  if [ -f "$target" ]; then
    got=$(shasum -a 256 "$target" | awk '{print $1}')
    if [ "$got" = "$expected" ]; then
      echo "$label already verified."
      return 0
    fi
    echo "$label has the wrong digest; replacing it." >&2
    rm -f "$target"
  fi

  if [ -n "$source_models" ] && [ -f "$source_models/$filename" ]; then
    got=$(shasum -a 256 "$source_models/$filename" | awk '{print $1}')
    if [ "$got" = "$expected" ]; then
      cp "$source_models/$filename" "$target.part"
      mv "$target.part" "$target"
      chmod 600 "$target"
      echo "$label copied from a verified local source."
      return 0
    fi
    echo "Local source for $label failed SHA-256 verification; downloading official asset." >&2
  fi

  echo "Downloading $label..."
  rm -f "$target.part"
  curl -L --fail --retry 5 --retry-all-errors --retry-delay 2 "$url" -o "$target.part"
  got=$(shasum -a 256 "$target.part" | awk '{print $1}')
  if [ "$got" != "$expected" ]; then
    rm -f "$target.part"
    echo "$label SHA-256 verification failed." >&2
    exit 1
  fi
  mv "$target.part" "$target"
  chmod 600 "$target"
}

install_model \
  "Whisper large-v3-turbo-q8_0" \
  "ggml-large-v3-turbo-q8_0.bin" \
  "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3-turbo-q8_0.bin?download=true" \
  "317eb69c11673c9de1e1f0d459b253999804ec71ac4c23c17ecf5fbe24e259a1"

install_model \
  "Whisper large-v3-q5_0 fallback" \
  "ggml-large-v3-q5_0.bin" \
  "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3-q5_0.bin?download=true" \
  "d75795ecff3f83b5faa89d1900604ad8c780abd5739fae406de19f23ecd98ad1"

install_model \
  "Silero VAD v6.2.0" \
  "ggml-silero-v6.2.0.bin" \
  "https://huggingface.co/ggml-org/whisper-vad/resolve/main/ggml-silero-v6.2.0.bin?download=true" \
  "2aa269b785eeb53a82983a20501ddf7c1d9c48e33ab63a41391ac6c9f7fb6987"

echo "RunOnMine local voice assets are ready in: $voice_dir"
