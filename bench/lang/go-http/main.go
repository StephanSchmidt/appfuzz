// appfuzz language test: a wasi:http handler in Go (TinyGo, net/http via
// wasi-http-go). It searches one fixed API for ?q= and shows the answer
// escaped. Its one bug is wasi-http-go's: a page over 4 KB goes to one
// blocking-write-and-flush, which wasmtime refuses above 4096 bytes.
package main

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"

	_ "github.com/ydnar/wasi-http-go/wasihttp"
)

func init() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		res, err := http.Get("https://api.example/search?q=" + url.QueryEscape(q))
		w.Header().Set("content-type", "text/html; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "<h1>Search is unavailable</h1>")
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		if res.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "<h1>Search is unavailable</h1>")
			return
		}
		fmt.Fprintf(w, "<h1>Results for %s</h1><pre>%s</pre>", html.EscapeString(q), html.EscapeString(string(body)))
	})
}

func main() {}
