// appfuzz language test: the n+1 bug from the Rust bench app `chatty`,
// written in TypeScript. Lists all items, then fetches each one again.
import { all, get } from "bench:web/items@0.1.0";

type Request = { method: string; path: string; query: [string, string][] };
type Response = { status: number; body: string; headers: [string, string][] };

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const handler = {
  handle(_req: Request): Response {
    let out = "<ul>";
    for (const it of all()) {
      try {
        const full = get(it.id);
        out += `<li>${esc(full.owner)}</li>`;
      } catch {
        // not found: skip
      }
    }
    out += "</ul>";
    return { status: 200, body: out, headers: [["content-type", "text/html"]] };
  },
};
