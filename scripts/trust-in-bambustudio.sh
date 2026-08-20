#!/usr/bin/env bash
# Add a certificate to BambuStudio's trust store, so it stops answering the
# proxy's TLS handshake with a fatal unknown_ca alert.
#
# Re-run this after every BambuStudio update: the app bundle is replaced
# wholesale (Homebrew cask upgrades and the in-app updater alike), which
# discards the modified trust store. Doing nothing else, it is idempotent.
#
# Usage: scripts/trust-in-bambustudio.sh <certificate.crt> [path/to/BambuStudio.app]

set -euo pipefail

cert=${1:-}
app=${2:-/Applications/BambuStudio.app}
store="$app/Contents/Resources/cert/printer.cer"

if [[ -z $cert ]]; then
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
[[ -r $cert ]] || { echo "error: cannot read $cert" >&2; exit 1; }
[[ -w $store ]] || { echo "error: cannot write $store" >&2; exit 1; }

# Compare fingerprints rather than text: whitespace and PEM line wrapping
# differ between sources, and a duplicated anchor is worth avoiding.
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
want=$(fingerprint "$cert")

# The store is a concatenation, so split it and fingerprint each anchor:
# there is no single openssl invocation that prints a fingerprint per
# certificate in a bundle.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
awk -v dir="$tmp" '
    /BEGIN CERTIFICATE/ { n++ }
    n { print > sprintf("%s/%03d.pem", dir, n) }
' "$store"

for anchor in "$tmp"/*.pem; do
    [[ -e $anchor ]] || break
    if [[ $(fingerprint "$anchor" 2>/dev/null) == "$want" ]]; then
        echo "already trusted: $want"
        exit 0
    fi
done

printf '\n' >> "$store"
cat "$cert" >> "$store"
echo "added $want"

# Modifying a sealed resource invalidates the app's signature. macOS normally
# still launches an app it has already assessed, but say so rather than let it
# be discovered later.
if ! codesign --verify "$app" 2>/dev/null; then
    echo
    echo "note: $app's signature is now invalid (a sealed resource changed)."
    echo "      If it refuses to launch, either re-sign it ad hoc:"
    echo "          codesign --force --deep --sign - $app"
    echo "      or reinstall the app: brew reinstall --cask bambu-studio"
fi
