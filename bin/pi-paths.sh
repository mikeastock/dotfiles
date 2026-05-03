#!/usr/bin/env bash

PI_MISE_TOOL="npm:@mariozechner/pi-coding-agent@latest"
PI_PACKAGE_NAME="@mariozechner/pi-coding-agent"
PI_PACKAGE_RELATIVE_PATH="lib/node_modules/$PI_PACKAGE_NAME"

pi_mise_install_root() {
  mise where "$PI_MISE_TOOL"
}

pi_package_root() {
  local install_root
  install_root="$(pi_mise_install_root)"
  printf '%s\n' "$install_root/$PI_PACKAGE_RELATIVE_PATH"
}
