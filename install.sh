#!/bin/sh
# Install appfuzz: curl -fsSL https://appfuzz.dev/install.sh | sh
#
# Downloads the prebuilt binary for this OS and CPU from the latest GitHub
# release, checks its SHA-256 and that it runs here, and puts it in
# ~/.local/bin (in /usr/local/bin when run as root, as in a container).
# Alpine, and a Linux too old for the glibc build, get the static build.
#
#   APPFUZZ_VERSION=v0.5.0   install this release instead of the latest
#   APPFUZZ_INSTALL_DIR=dir  install here instead
#
# Source: https://github.com/StephanSchmidt/appfuzz/blob/main/install.sh

# Everything is in main(), which runs on the last line, so a download cut
# short never runs half a script.
main() {
  set -eu
  repo="StephanSchmidt/appfuzz"
  version="${APPFUZZ_VERSION:-latest}"
  if [ "$(id -u)" = 0 ]; then
    dir="${APPFUZZ_INSTALL_DIR:-/usr/local/bin}"
  else
    dir="${APPFUZZ_INSTALL_DIR:-$HOME/.local/bin}"
  fi
  from_source="build from source: cargo install --git https://github.com/$repo appfuzz"

  case "$(uname -s)" in
    Linux)
      # Alpine and other musl systems can't load the glibc build.
      os="unknown-linux-gnu"
      for loader in /lib/ld-musl-*; do
        [ -e "$loader" ] && os="unknown-linux-musl"
      done
      ;;
    Darwin) os="apple-darwin" ;;
    *) die "no prebuilt binary for $(uname -s); $from_source" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) die "no prebuilt binary for $(uname -m); $from_source" ;;
  esac
  # A shell running under Rosetta reports x86_64 on an Apple Silicon Mac.
  if [ "$os" = "apple-darwin" ] && [ "$arch" = "x86_64" ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
    arch="aarch64"
  fi
  if [ "$version" = "latest" ]; then
    base="https://github.com/$repo/releases/latest/download"
  else
    base="https://github.com/$repo/releases/download/$version"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM

  # Run it before installing it, so a binary this system can't run never
  # replaces one that works.
  get "$arch-$os"
  if ! runs && [ "$os" = "unknown-linux-gnu" ]; then
    say "the glibc build does not run on this Linux; trying the static build"
    os="unknown-linux-musl"
    get "$arch-$os"
  fi
  runs || die "the prebuilt binary does not run here: $(printf '%s\n' "$installed" | head -n 1); $from_source"
  mkdir -p "$dir"
  # Move into place, so a running appfuzz is replaced, not overwritten.
  cp "$tmp/appfuzz" "$dir/appfuzz.new"
  chmod 755 "$dir/appfuzz.new"
  mv -f "$dir/appfuzz.new" "$dir/appfuzz"

  say "installed $installed to $dir/appfuzz"
  # A piped script can't change the PATH of the shell that ran it, so the
  # commands below must work as printed.
  case ":$PATH:" in
    *":$dir:"*) cmd="appfuzz" ;;
    *)
      cmd="$dir/appfuzz"
      say "$dir is not on your PATH; add it in your shell profile: export PATH=\"$dir:\$PATH\""
      ;;
  esac
  say "try it: $cmd --human https://appfuzz.dev/demo/chatty.wasm"
  say "on your app: $cmd --wasm my_app.wasm review"
}

say() { printf 'appfuzz: %s\n' "$1"; }
die() { printf 'appfuzz: error: %s\n' "$1" >&2; exit 1; }

# Downloads appfuzz-<target>.tar.gz into $tmp, checks its SHA-256 and
# unpacks it.
get() {
  file="appfuzz-$1.tar.gz"
  case "$1" in
    *-musl) missing=" (older releases have no static build; $from_source)" ;;
    *) missing="" ;;
  esac
  say "downloading $file ($version)"
  fetch "$base/$file" "$tmp/$file" || die "download failed: $base/$file$missing"
  fetch "$base/$file.sha256" "$tmp/$file.sha256" || die "download failed: $base/$file.sha256"

  want="$(cut -d ' ' -f 1 <"$tmp/$file.sha256")"
  got="$(sha256 "$tmp/$file")"
  [ "$want" = "$got" ] || die "checksum mismatch for $file: expected $want, got $got"
  tar -xzf "$tmp/$file" -C "$tmp"
}

# Runs the unpacked binary; $installed is its version, or why it failed.
runs() { installed="$("$tmp/appfuzz" --version 2>&1)"; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1"
  else
    die "need curl or wget"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    die "need sha256sum or shasum to check the download"
  fi
}

main "$@"
