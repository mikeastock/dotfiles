if command -v brew >/dev/null 2>&1; then
  eval "$(brew shellenv)"
fi

# asdf
export PATH="${ASDF_DATA_DIR:-$HOME/.asdf}/shims:$PATH"

# mise
eval "$(mise activate zsh)"

export PATH="$HOME/.local/bin:$PATH"

if [ -f "$HOME/.env" ]; then
  set -a
  . "$HOME/.env"
  set +a
fi
