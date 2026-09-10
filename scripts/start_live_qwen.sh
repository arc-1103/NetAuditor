#!/usr/bin/env bash
set -euo pipefail

LLAMA_BIN="${LLAMA_BIN:-$HOME/.local/bin/llama}"
QWEN_MODEL="${QWEN_MODEL:-Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF:Q4_K_M}"
QWEN_PORT="${QWEN_PORT:-11435}"

test -x "$LLAMA_BIN" || { echo "llama runtime not found at $LLAMA_BIN" >&2; exit 1; }
echo "Starting real local Qwen model on http://127.0.0.1:$QWEN_PORT"
exec "$LLAMA_BIN" serve -hf "$QWEN_MODEL" --host 127.0.0.1 --port "$QWEN_PORT"
