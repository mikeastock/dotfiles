# asdf
export PATH="${ASDF_DATA_DIR:-$HOME/.asdf}/shims:$PATH"

# mise
eval "$(mise activate zsh)"

if [ -f "$HOME/.env" ]; then
  set -a
  . "$HOME/.env"
  set +a
fi
