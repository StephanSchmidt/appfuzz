#!/bin/sh
# Renders OUT/demo.{gif,webm,mp4} from bench/demo.tape, and its last frame
# as OUT/demo.png (the video's poster); demo-narrow.* the same at phone
# width. OUT is the first argument, by default the website's static/ next to
# this repo (../appfuzz-website/static).
# Needs vhs (brew install vhs). Builds appfuzz and the demo apps, serves
# them on localhost, and records a review of chatty.
set -eu
cd "$(dirname "$0")/.."
out=${1:-../appfuzz-website/static}
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'kill $server 2>/dev/null; rm -rf "$tmp"' EXIT
cargo build -q --release --bin appfuzz
bench/demo.sh "$tmp/demo" >/dev/null
port=8798
(cd "$tmp" && exec python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1) &
server=$!
sleep 1
sed -e "s|^Output OUT/|Output $out/|" bench/demo.tape > "$tmp/wide.tape"
sed -e "s|^Output OUT/demo\.|Output $out/demo-narrow.|" -e 's/^Set Width .*/Set Width 640/' \
    -e 's/^Set Height .*/Set Height 860/' -e 's/^Set FontSize .*/Set FontSize 16/' \
    -e 's/^Set Padding .*/Set Padding 16/' bench/demo.tape > "$tmp/narrow.tape"
for tape in "$tmp/wide.tape" "$tmp/narrow.tape"; do
    APPFUZZ_BIN="$PWD/target/release/appfuzz" APPFUZZ_CACHE="$tmp/cache" DEMO_PORT=$port vhs "$tape"
done
rm -f "$out/demo-narrow.gif"
for v in demo demo-narrow; do
    ffmpeg -v error -y -sseof -0.5 -i "$out/$v.webm" -frames:v 1 "$out/$v.png"
done
ls -la "$out"/demo*
