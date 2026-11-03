#!/bin/sh
# Writes the Homebrew formula for a release to stdout.
#
#   .github/homebrew/render.sh 0.3.0 dist > appfuzz.rb
#
# dist holds the release's appfuzz-<target>.tar.gz.sha256 files.
set -eu
version="$1"
dist="$2"
tmpl="$(dirname "$0")/appfuzz.rb.tmpl"
args="-e s/@VERSION@/$version/g"
for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  sha="$(cut -d ' ' -f 1 <"$dist/appfuzz-$target.tar.gz.sha256")"
  case "$sha" in
    *[!0-9a-f]* | "") echo "bad checksum for $target: '$sha'" >&2; exit 1 ;;
  esac
  [ "${#sha}" -eq 64 ] || { echo "bad checksum for $target: '$sha'" >&2; exit 1; }
  args="$args -e s/@SHA_$target@/$sha/g"
done
# shellcheck disable=SC2086
out="$(sed $args "$tmpl")"
case "$out" in
  *@*@*) echo "unfilled placeholder in formula" >&2; exit 1 ;;
esac
printf '%s\n' "$out"
