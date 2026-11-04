# Sourced by bench/demo.tape: `appfuzz` reviews the local copy of the demo
# apps that bench/record.sh serves, and prints the public URLs, so the
# recording shows what `appfuzz https://appfuzz.dev/demo/...` prints.
export PS1='\[\e[38;5;245m\]$\[\e[0m\] '
appfuzz() {
    local args=()
    for a in "$@"; do args+=("${a//https:\/\/appfuzz.dev/http://127.0.0.1:${DEMO_PORT}}"); done
    COLUMNS=$(tput cols) CLICOLOR_FORCE=1 "$APPFUZZ_BIN" "${args[@]}" --allow-http 2>&1 |
        sed -e "s|http://127.0.0.1:${DEMO_PORT}|https://appfuzz.dev|g" -e 's| --allow-http||g'
}
