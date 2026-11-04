// A wasi:http handler in JavaScript (StarlingMonkey fetch event): looks up
// a stock quote from one fixed API and escapes what it shows.

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname !== "/") {
    return new Response("<h1>Not found</h1>", { status: 404, headers: { "content-type": "text/html" } });
  }
  const symbol = (url.searchParams.get("symbol") || "ACME").slice(0, 12);
  let text;
  try {
    const r = await fetch(`https://api.example/quote?symbol=${encodeURIComponent(symbol)}`);
    if (!r.ok) throw new Error(`status ${r.status}`);
    text = (await r.text()).slice(0, 500);
  } catch (e) {
    return new Response("<h1>Quotes are unavailable</h1>", { status: 502, headers: { "content-type": "text/html" } });
  }
  return new Response(`<h1>${esc(symbol)}</h1><p>${esc(text)}</p>`, { headers: { "content-type": "text/html" } });
}

addEventListener("fetch", (event) => event.respondWith(handle(event.request)));
