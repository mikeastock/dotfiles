---
summary: "Scaffold checklist for a new macOS menu bar app with Sparkle updates"
read_when:
  - Scaffolding a new macOS menu bar app with Sparkle.
---

# New macOS App Scaffold (Sparkle + DevID + shared release flow)

This is a practical, minimal checklist to get a new macOS (SwiftPM) menubar app ready for distribution via Sparkle and our shared release scripts.

## 1) Project skeleton
- SwiftPM package with `Resources` for assets and `Package.swift` targeting macOS 15+.
- Add Sparkle dependency in `Package.swift`:
  - `.package(url: "https://github.com/sparkle-project/Sparkle", from: "2.8.1")`
  - Target dependency: `.product(name: "Sparkle", package: "Sparkle")`
- Menubar entry point (MenuBarExtra) plus a thin Sparkle wrapper that enables updates only for signed/bundled builds.

## 2) Bundle identifiers & feeds
- Pick bundle id: `com.steipete.<appname>` (no uppercase, no spaces).
- Appcast URL: `https://raw.githubusercontent.com/steipete/<Repo>/main/appcast.xml`
- Embed in Info.plist (or generated plist in packaging script):
  - `SUFeedURL` = appcast URL
  - `SUPublicEDKey` = Sparkle ed25519 public key (from your key pair)
  - `SUEnableInstallerLauncherService` = true

## 3) Sparkle keys
- Use the existing shared key unless the app must have its own. Keys live outside repos.
- Private key: base64, **single line, no comments**. Export path via `SPARKLE_PRIVATE_KEY_FILE`.
- Public key goes into Info.plist. Example shared public key: `AGCY8w5vHirVfGGDGc8Szc5iuOqupZSh9pMj/Qs67XI=`

## 4) Packaging & signing scripts (SwiftPM)
- Add to `Scripts/`:
  - `package_app.sh` (build, write Info.plist with bundle id/version/Sparkle keys, codesign in debug or skip if not set).
  - `sign-and-notarize.sh` (release build, DevID sign, notarize, zip app + dSYM, enforce key cleanliness).
  - `release.sh` sourcing `~/Projects/agent-scripts/release/sparkle_lib.sh` to: lint/test, sign+notarize, clear caches, verify appcast/enclosure, optional live-update test, create GH release, check assets, tag/push.
  - `check-release-assets.sh` thin wrapper that calls `check_assets` from shared lib.
  - `test_live_update.sh` (optional manual update smoke test, gated by `RUN_SPARKLE_UPDATE_TEST=1`).
- Keep `version.env` as the single source for `MARKETING_VERSION` and `BUILD_NUMBER`.

## 5) Appcast
- Create `appcast.xml` with an empty channel header:
  ```xml
  <?xml version="1.0" standalone="yes"?>
  <rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
      <channel>
          <title><AppName></title>
      </channel>
  </rss>
  ```
- `release.sh` should insert a new `<item>` per release (version, build, signature, length, enclosure URL).

## 6) Required env vars for releases
- `SPARKLE_PRIVATE_KEY_FILE` (single-line base64 key; no comments)
- `APP_STORE_CONNECT_API_KEY_P8`, `APP_STORE_CONNECT_KEY_ID`, `APP_STORE_CONNECT_ISSUER_ID`
- Optional: `RUN_SPARKLE_UPDATE_TEST=1` to force the manual live-update check.

## 7) Release flow (shared pattern)
1. `git status` clean.
2. Update `version.env` + changelog.
3. `Scripts/release.sh` (runs lint/test, sign/notarize, appcast verify, GH release, asset check, tag/push). 
4. If `RUN_SPARKLE_UPDATE_TEST=1`, perform manual update confirmation.

## 8) Verification checklist
- `verify_appcast_entry` passes (signatures & length match).
- Enclosure URL returns 200 and matches appcast signature.
- `spctl`, `codesign --verify --deep --strict`, `stapler validate` pass on the notarized app.
- GH release has both zip and dSYM.
- Previous build can update via Sparkle (optional but recommended for major releases).

## 9) Common gotchas
- Sparkle private key file must not contain comments or blank lines—scripts will fail fast.
- Bundle id must match codesign identity & appcast entry; SUPublicEDKey must match the signing key pair.
- Before zipping a notarized app, run `xattr -cr <App>.app` and delete `._*` files, then zip with `ditto --norsrc -c -k --keepParent …` to avoid AppleDouble files that break code signatures. When testing, extract with `ditto -x -k` (not `unzip`).
- Shared release helpers now always download the enclosure, check the ed25519 signature, and run `codesign --verify` + `spctl` on the extracted app before publish—no env flag needed.
- Build numbers must monotonically increase; Sparkle compares `CFBundleVersion`.

## 10) Files to add in a new repo
- `version.env`
- `appcast.xml`
- `Scripts/`: `package_app.sh`, `sign-and-notarize.sh`, `release.sh`, `check-release-assets.sh`, `test_live_update.sh`, `validate_changelog.sh` (if desired)
- Update `Package.swift` to include Sparkle.

With these pieces in place, the app will align with CodexBar/Trimmy/RepoBar release hardening and shared Sparkle verification.
