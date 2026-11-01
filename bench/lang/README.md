# Language tests

The `chatty` bench app (list all items, then fetch each one again: an n+1)
written in other languages, built against the same WIT (`../wit/web.wit`,
world `items-app`) and reviewed with the same manifest limits.

| App | Language | Toolchain | Component |
|-----|----------|-----------|-----------|
| `../apps/chatty` | Rust | cargo, wasm32-wasip2 | 65 KB |
| `ts-chatty` | TypeScript | jco + componentize-js (StarlingMonkey) | 12 MB |
| `py-chatty` | Python | componentize-py 0.25 | 18 MB |

Fuzz speed on a 24-thread machine (`fuzz --time 5s`): Rust about 11,800
runs/s, TypeScript about 1,850, Python about 1,750.

Build:

```sh
cd ts-chatty && npm install && npx jco componentize src/app.ts \
    --wit ../../wit/web.wit --world-name items-app --disable all -o app.wasm
cd py-chatty && uvx componentize-py -d ../../wit/web.wit -w items-app \
    componentize app -o app.wasm
```

Then `appfuzz review` in each directory.

## What review finds

All three: `n_plus_1` (calls to items#get grow as 1·n, cost breaks its limit
at n = 100), `over_budget` (129 cost), `chatty`, `redundant_calls`,
`serial_chain`, with the same titles.

Per language:

- **TypeScript** also fails `hang` / `over_budget` on fuel: with 32 items
  whose fields are 10 KB strings, the four regex `replace` calls in `esc`
  cost about 27M fuel per item in the JS engine (Rust: 9.9M fuel for all
  32), so the run hits the 200M limit.
- **Python** also fails `ungranted_import` eight times: the
  componentize-py runtime imports `wasi:filesystem` and `wasi:sockets`
  whatever the app uses.
- **Worlds:** componentize-js and componentize-py import every interface of
  the world they are built against, so build against a world with only the
  imports the app uses (`items-app`), or appfuzz reports the rest as
  ungranted.

## What is weaker for interpreted languages

Coverage guidance sees the interpreter's branches, not the script's, and
static findings (`host_call_in_loop`, `wasm disasm`, `profile`) point at
interpreter functions. Each run boots the engine, so there are fewer runs per
second than for Rust.
