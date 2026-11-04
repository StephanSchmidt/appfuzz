#!/bin/sh
# Renders website/demo.{gif,webm,mp4} from bench/demo.tape, and its last
# frame as website/demo.png (the video's poster); demo-narrow.* the same
# at phone width.
# Needs vhs (brew install vhs). Builds appfuzz and the demo apps, serves
# them on localhost, and records a review of chatty.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'kill $server 2>/dev/null; rm -rf "$tmp"' EXIT
cargo build -q --release --bin appfuzz
bench/demo.sh "$tmp/demo" >/dev/null
port=8798
(cd "$tmp" && exec python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1) &
server=$!
sleep 1
sed -e 's|website/demo\.|website/demo-narrow.|' -e 's/^Set Width .*/Set Width 640/' \
    -e 's/^Set Height .*/Set Height 860/' -e 's/^Set FontSize .*/Set FontSize 16/' \
    -e 's/^Set Padding .*/Set Padding 16/' bench/demo.tape > "$tmp/narrow.tape"
for tape in bench/demo.tape "$tmp/narrow.tape"; do
    APPFUZZ_BIN="$PWD/target/release/appfuzz" APPFUZZ_CACHE="$tmp/cache" DEMO_PORT=$port vhs "$tape"
done
rm -f website/demo-narrow.gif
for v in demo demo-narrow; do
    ffmpeg -v error -y -sseof -0.5 -i "website/$v.webm" -frames:v 1 "website/$v.png"
done
ls -la website/demo.*
