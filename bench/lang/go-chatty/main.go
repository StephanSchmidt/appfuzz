// appfuzz language test: the n+1 bug from the Rust bench app `chatty`,
// written in Go for TinyGo. Lists all items, then fetches each one again.
package main

import (
	"strings"

	"go-chatty/gen/bench/web/handler"
	"go-chatty/gen/bench/web/items"

	"go.bytecodealliance.org/cm"
)

var esc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace

func init() {
	handler.Exports.Handle = func(req handler.Request) handler.Response {
		out := "<ul>"
		for _, it := range items.All().Slice() {
			if full, _, isErr := items.Get(it.ID).Result(); !isErr {
				out += "<li>" + esc(full.Owner) + "</li>"
			}
		}
		out += "</ul>"
		headers := cm.ToList([][2]string{{"content-type", "text/html"}})
		return handler.Response{Status: 200, Body: out, Headers: headers}
	}
}

func main() {}
