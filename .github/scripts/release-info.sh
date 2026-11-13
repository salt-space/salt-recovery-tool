#!/usr/bin/env bash
# Helpers for .github/workflows/release.yml (also runnable locally).
#   release-info.sh version     print the app version; fails unless package.json,
#                               src-tauri/tauri.conf.json and Cargo.toml agree
#   release-info.sh notes VER   print the release notes: the CHANGELOG.md section
#                               for VER, then download and verification notes
set -euo pipefail
cd "$(dirname "$0")/../.."

case "${1:-}" in
  version)
    pkg=$(node -p 'require("./package.json").version')
    tauri=$(node -p 'require("./src-tauri/tauri.conf.json").version')
    cargo=$(sed -n '/^\[workspace\.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' Cargo.toml)
    if [ "$pkg" != "$tauri" ] || [ "$pkg" != "$cargo" ]; then
      echo "version mismatch: package.json $pkg, src-tauri/tauri.conf.json $tauri, Cargo.toml $cargo" >&2
      exit 1
    fi
    echo "$pkg"
    ;;

  notes)
    version=${2:?usage: release-info.sh notes VERSION}
    # Section starts at "## VERSION" or "## VERSION (date)" and runs to the next "## ".
    section=$(awk -v h="## $version" '
      index($0, h) == 1 && (length($0) == length(h) || substr($0, length(h) + 1, 1) == " ") { found = 1; next }
      found && /^## / { exit }
      found { print }
    ' CHANGELOG.md | sed -e '/./,$!d')
    if [ -z "$section" ]; then
      echo "CHANGELOG.md has no \"## $version\" section" >&2
      exit 1
    fi
    cat <<EOF
$section

## Downloads

| Platform | Installers | Portable binary (GUI + headless CLI) |
|---|---|---|
| Linux x64 | \`.AppImage\`, \`.deb\`, \`.rpm\` | \`salt-recovery-tool-linux-x64\` |
| macOS (Intel + Apple Silicon) | \`.dmg\` | \`salt-recovery-tool-macos-universal\` |
| Windows x64 | \`-setup.exe\`, \`.msi\` | \`salt-recovery-tool-win-x64.exe\` |

Dependency licence texts and notices are included in \`THIRD_PARTY_LICENSES.zip\`.

Check downloads against \`SHA256SUMS.txt\`, e.g. \`sha256sum -c SHA256SUMS.txt --ignore-missing\`.
On Linux and macOS, make a portable binary executable with \`chmod +x\` first.
macOS builds are ad-hoc signed and not notarized: open the app with right-click, then Open, the first time.
EOF
    ;;

  *)
    echo "usage: release-info.sh version | notes VERSION" >&2
    exit 2
    ;;
esac
