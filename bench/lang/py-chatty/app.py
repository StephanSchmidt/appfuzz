# appfuzz language test: the n+1 bug from the Rust bench app `chatty`,
# written in Python. Lists all items, then fetches each one again.
from html import escape

from componentize_py_types import Err
from wit_world import exports
from wit_world.imports import items
from wit_world.imports.types import Request, Response


class Handler(exports.Handler):
    def handle(self, req: Request) -> Response:
        out = "<ul>"
        for it in items.all():
            try:
                full = items.get(it.id)
                out += f"<li>{escape(full.owner)}</li>"
            except Err:
                pass  # not found: skip
        out += "</ul>"
        return Response(200, out, [("content-type", "text/html")])
