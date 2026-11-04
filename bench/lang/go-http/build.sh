#!/bin/sh
# Build go-http with TinyGo (wasip2) and wasi-http-go. Needs tinygo and go
# on PATH.
set -eu
cd "$(dirname "$0")"
go mod tidy
dir=$(go list -m -f '{{.Dir}}' github.com/ydnar/wasi-http-go)
cat > target.json <<JSON
{
	"inherits": ["wasip2"],
	"wit-package": "$dir/internal/go/http/proxy/proxy.wit",
	"wit-world": "go:http/proxy"
}
JSON
tinygo build -target=target.json -opt=2 -o app.wasm .
rm target.json
