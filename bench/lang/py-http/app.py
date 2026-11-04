"""A wasi:http handler in Python (componentize-py, asyncio poll loop).

It posts the visitor's name to one fixed API and greets them. The bug: the
name goes into the page unescaped (reflection).
"""

import asyncio
import json
from urllib.parse import urlparse, parse_qs

import poll_loop
from componentize_py_types import Ok
from poll_loop import PollLoop, Sink, Stream
from wit_world import exports
from wit_world.imports.types import (
    Fields, IncomingRequest, Method_Post, OutgoingBody, OutgoingRequest,
    OutgoingResponse, ResponseOutparam, Scheme_Https,
)


class IncomingHandler(exports.IncomingHandler):
    def handle(self, request: IncomingRequest, response_out: ResponseOutparam):
        loop = PollLoop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(handle_async(request, response_out))


async def fetch_greeting(name: str) -> str:
    req = OutgoingRequest(Fields.from_list([("content-type", b"application/json")]))
    req.set_method(Method_Post())
    req.set_scheme(Scheme_Https())
    req.set_authority("api.example")
    req.set_path_with_query("/greeting")
    sink = Sink(req.body())
    response = asyncio.ensure_future(poll_loop.send(req))
    await sink.send(json.dumps({"name": name}).encode())
    sink.close()
    resp = await response
    if resp.status() != 200:
        return "Hello"
    stream = Stream(resp.consume())
    text = b""
    while (chunk := await stream.next()) is not None:
        text += chunk
    return text.decode("utf-8", "replace")[:100]


async def handle_async(request: IncomingRequest, response_out: ResponseOutparam):
    pq = request.path_with_query() or "/"
    name = parse_qs(urlparse(pq).query).get("name", ["friend"])[0][:40]
    try:
        greeting = await fetch_greeting(name)
    except Exception:
        greeting = "Hello"
    html = f"<h1>{greeting.replace('<', '&lt;')}, {name}!</h1>".encode()
    response = OutgoingResponse(Fields.from_list([("content-type", b"text/html")]))
    body = response.body()
    ResponseOutparam.set(response_out, Ok(response))
    sink = Sink(body)
    await sink.send(html)
    sink.close()


