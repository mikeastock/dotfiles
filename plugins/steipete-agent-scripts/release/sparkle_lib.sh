#!/usr/bin/env bash
set -euo pipefail

# Shared Sparkle/release helpers for CodexBar/Trimmy/RepoBar.
# Expected env/args:
#   SPARKLE_PRIVATE_KEY_FILE : path to ed25519 private key (comment-free)
#   APPCAST                  : path to appcast.xml
#   APP_NAME                 : e.g. CodexBar
#   ARTIFACT_PREFIX          : e.g. CodexBar-
#   BUNDLE_ID                : e.g. com.steipete.codexbar
#   VERSION                  : marketing version (e.g. 0.5.6)
#   BUILD_NUMBER             : build (sparkle:version) if needed

require_bin() {
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 || { echo "Missing required tool: $b" >&2; exit 1; }
  done
}

# Ensures the git working tree is clean before a release.
require_clean_worktree() {
  require_bin git
  if [[ -n $(git status --porcelain) ]]; then
    echo "Working tree is not clean; commit or stash first." >&2
    exit 1
  fi
}

clean_key() {
  local keyfile=${1:?"key file required"}
  if [[ ! -f "$keyfile" ]]; then
    echo "Sparkle key file not found: $keyfile" >&2
    exit 1
  fi
  local lines
  lines=$(grep -v '^[[:space:]]*#' "$keyfile" | sed '/^[[:space:]]*$/d')
  if [[ $(printf "%s\n" "$lines" | wc -l) -ne 1 ]]; then
    echo "Sparkle key must be a single base64 line (no comments/blank lines)." >&2
    exit 1
  fi
  local tmp
  tmp=$(mktemp)
  printf "%s" "$lines" >"$tmp"
  echo "$tmp"
}

# Quick sanity check that the Sparkle key can sign content.
probe_sparkle_key() {
  local keyfile=${1:?"key file required"}
  require_bin sign_update
  local tmp
  tmp=$(mktemp /tmp/sparkle-key-probe.XXXX)
  echo test >"$tmp"
  sign_update --ed-key-file "$keyfile" -p "$tmp" >/dev/null
  rm -f "$tmp"
}

verify_enclosure() {
  local url=$1 sig=$2 keyfile=$3 expected_len=$4
  require_bin curl sign_update
  local tmp
  tmp=$(mktemp /tmp/sparkle-enclosure.XXXX)
  trap '[[ -n ${tmp:-} ]] && rm -f "$tmp"' RETURN
  curl -L -o "$tmp" "$url"
  local len
  len=$(stat -f%z "$tmp")
  if [[ "$len" != "$expected_len" ]]; then
    echo "Length mismatch for $url (expected $expected_len, got $len)" >&2
    exit 1
  fi
  sign_update --verify "$tmp" "$sig" --ed-key-file "$keyfile"
}

verify_appcast_entry() {
  local appcast=${1:?"appcast path"} version=${2:?"version"} keyfile=${3:?"key file"}
  require_bin python3 curl sign_update
  local tmp_meta
  tmp_meta=$(mktemp)
  trap '[[ -n ${tmp_meta:-} ]] && rm -f "$tmp_meta"' RETURN

  python3 - "$appcast" "$version" >"$tmp_meta" <<'PY'
import sys, xml.etree.ElementTree as ET
appcast, version = sys.argv[1], sys.argv[2]
root = ET.parse(appcast).getroot()
ns = {"sparkle": "http://www.andymatuschak.org/xml-namespaces/sparkle"}
entry = None
for item in root.findall("./channel/item"):
    if item.findtext("sparkle:shortVersionString", default="", namespaces=ns) == version:
        entry = item
        break
if entry is None:
    sys.exit("No appcast entry for version {}".format(version))
enc = entry.find("enclosure")
url = enc.get("url")
sig = enc.get("{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature")
length = enc.get("length")
if not (url and sig and length):
    sys.exit("Missing url/signature/length for version {}".format(version))
print(url)
print(sig)
print(length)
PY

  # Bash 3.2 (macOS default) has no `readarray`/`mapfile`; parse lines portably.
  local url sig length
  url=$(sed -n '1p' "$tmp_meta")
  sig=$(sed -n '2p' "$tmp_meta")
  length=$(sed -n '3p' "$tmp_meta")
  verify_enclosure "$url" "$sig" "$keyfile" "$length"
  echo "Appcast entry $version verified (signature & length)."
  verify_codesign_from_enclosure "$url"
}

check_assets() {
  local tag=${1:?"tag"} prefix=${2:?"artifact prefix"} repo
  require_bin gh
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
  local assets
  assets=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')
  local zip dsym
  zip=$(printf "%s\n" "$assets" | grep -E "^${prefix}[0-9]+(\\.[0-9]+)*(-[0-9A-Za-z.]+)?\\.zip$" || true)
  dsym=$(printf "%s\n" "$assets" | grep -E "^${prefix}[0-9]+(\\.[0-9]+)*(-[0-9A-Za-z.]+)?\\.dSYM\\.zip$" || true)
  [[ -z "$zip" ]] && { echo "ERROR: app zip missing on release $tag" >&2; exit 1; }
  [[ -z "$dsym" ]] && { echo "ERROR: dSYM zip missing on release $tag" >&2; exit 1; }
  echo "Release $tag has zip ($zip) and dSYM ($dsym)."
}

clear_sparkle_caches() {
  rm -rf ~/Library/Caches/${1} ~/Library/Caches/org.sparkle-project.Sparkle || true
}

# Removes AppleDouble/extended attributes that break codesign after zipping.
clean_macos_metadata() {
  local path=${1:?"path required"}
  xattr -cr "$path" 2>/dev/null || true
  find "$path" -name '._*' -delete 2>/dev/null || true
}

# Zips a bundle without resource-fork baggage.
safe_zip() {
  local source=${1:?"source bundle/app required"} dest=${2:?"destination zip required"}
  clean_macos_metadata "$source"
  /usr/bin/ditto --norsrc -c -k --keepParent "$source" "$dest"
}

# Download an enclosure, extract, and verify codesign/spctl on the bundled app.
verify_codesign_from_enclosure() {
  local url=${1:?"enclosure URL required"}
  require_bin curl ditto codesign spctl

  local tmp_dir tmp_zip
  tmp_dir=$(mktemp -d /tmp/sparkle-verify.XXXX)
  tmp_zip="$tmp_dir/enclosure.zip"
  curl -L -o "$tmp_zip" "$url"

  # Extract without resource forks to avoid introducing AppleDouble files.
  /usr/bin/ditto -x -k --norsrc "$tmp_zip" "$tmp_dir"

  local app
  # `ditto -c -k --sequesterRsrc` creates an `__MACOSX/` sidecar on extract; ignore it.
  app=$(find "$tmp_dir" -maxdepth 2 -name "*.app" -not -path "*/__MACOSX/*" | head -n 1)
  if [[ -z "$app" ]]; then
    app=$(find "$tmp_dir" -maxdepth 2 -name "*.app" | head -n 1)
  fi
  if [[ -z "$app" ]]; then
    echo "No .app found in enclosure $url" >&2
    return 1
  fi

  if ! codesign --verify --deep --strict --verbose "$app"; then
    echo "codesign verification failed for $app" >&2
    return 1
  fi
  if ! spctl --assess --type execute --verbose "$app"; then
    echo "spctl assessment failed for $app" >&2
    return 1
  fi
  if command -v stapler >/dev/null 2>&1; then
    stapler validate "$app" >/dev/null || true
  fi
  echo "Codesign/spctl verification OK for $(basename "$app") from $url"
}

# Ensure changelog top section matches the version and is finalized (not Unreleased).
ensure_changelog_finalized() {
  local version=${1:?"version required"}
  require_bin python3
  python3 - "$version" <<'PY'
import sys, pathlib, re
version = sys.argv[1]
p = pathlib.Path("CHANGELOG.md")
text = p.read_text()
first = re.search(r"^##\s+(.+)$", text, re.M)
if not first:
    sys.exit("No changelog sections found")
header = first.group(1)
if "Unreleased" in header:
    sys.exit("Top changelog section still marked Unreleased")
if not header.startswith(f"{version} ") and not header.startswith(f"{version} —"):
    sys.exit(f"Top changelog section '{header}' does not match version {version}")
if not re.search(rf"^##\s+{re.escape(version)}\s+", text, re.M):
    sys.exit(f"No section found for version {version}")
PY
}

# Extract release notes for VERSION from CHANGELOG.md into DEST path.
extract_notes_from_changelog() {
  local version=${1:?"version required"}
  local dest=${2:?"dest path required"}
  require_bin python3
  python3 - "$version" "$dest" <<'PY'
import sys, pathlib, re
version, dest = sys.argv[1], pathlib.Path(sys.argv[2])
text = pathlib.Path("CHANGELOG.md").read_text()
pattern = re.compile(rf"^##\s+{re.escape(version)}\s+.*$", re.M)
m = pattern.search(text)
if not m:
    sys.exit("section not found")
start = m.end()
next_header = text.find("\n## ", start)
chunk = text[start: next_header if next_header != -1 else len(text)]
lines = [ln for ln in chunk.strip().splitlines() if ln.strip()]
dest.write_text("\n".join(lines) + "\n")
PY
}

# Reads the latest appcast entry (top item) returning version and build to stdout.
appcast_head_version_build() {
  local appcast=${1:-appcast.xml}
  require_bin python3
  python3 - "$appcast" <<'PY'
import sys, xml.etree.ElementTree as ET
appcast = sys.argv[1]
root = ET.parse(appcast).getroot()
channel = root.find('channel')
if channel is None:
    sys.exit(1)
item = channel.find('item')
if item is None:
    sys.exit(1)
ns = {'sparkle': 'http://www.andymatuschak.org/xml-namespaces/sparkle'}
ver = item.findtext('sparkle:shortVersionString', default='', namespaces=ns)
build = item.findtext('sparkle:version', default='', namespaces=ns)
print(ver)
print(build)
PY
}

# Ensures the target version/build advance beyond the current appcast head.
ensure_appcast_monotonic() {
  local appcast=${1:-appcast.xml} version=${2:?"version required"} build=${3:?"build required"}
  local current
  current=$(appcast_head_version_build "$appcast" || true)
  local cur_ver cur_build
  cur_ver=$(printf "%s\n" "$current" | sed -n '1p')
  cur_build=$(printf "%s\n" "$current" | sed -n '2p')
  if [[ -n "$cur_ver" && "$cur_ver" == "$version" ]]; then
    echo "appcast already has version $version; bump version first." >&2
    exit 1
  fi
  if [[ -n "$cur_build" && "$build" -le "$cur_build" ]]; then
    echo "Build number $build must be greater than latest appcast build $cur_build." >&2
    exit 1
  fi
}
