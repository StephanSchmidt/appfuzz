# Language tests

The `chatty` bench app (list all items, then fetch each one again: an n+1)
written in other languages, built against the same WIT (`../wit/web.wit`,
world `items-app`) and reviewed with the same manifest limits.

| App | Language | Toolchain | Component |
|-----|----------|-----------|-----------|
| `../apps/chatty` | Rust | cargo, wasm32-wasip2 | 65 KB |
| `ts-chatty` | TypeScript | jco + componentize-js (StarlingMonkey) | 12 MB |
| `js-chatty` | JavaScript | jco + componentize-js (StarlingMonkey) | 12 MB |
| `go-chatty` | Go | TinyGo 0.44 (wasip2) + wit-bindgen-go | 784 KB |
| `cs-chatty` | C# | .NET 10 + componentize-dotnet (NativeAOT-LLVM) | 2.3 MB |
| `py-chatty` | Python | componentize-py 0.25 | 18 MB |
| `zig-chatty` | Zig | zig 0.17 + wit-bindgen c + preview1 adapter | 114 KB |

Fuzz speed on an AMD Ryzen 9 3900X, 24 threads (`fuzz --time 30s`, fresh
state): Rust 17,900 to 26,500 runs/s over five runs, Zig 9,500 to 9,900 over three.
The count depends on what the search tries: huge lists take longer. TypeScript
1,900 and Python 1,940 are from one earlier run each.

Build:

```sh
cd ts-chatty && npm install && npx jco componentize src/app.ts \
    --wit ../../wit/web.wit --world-name items-app --disable all -o app.wasm
cd py-chatty && uvx componentize-py -d ../../wit/web.wit -w items-app \
    componentize app -o app.wasm
cd js-chatty && ../ts-chatty/node_modules/.bin/jco componentize app.js \
    --wit ../../wit/web.wit --world-name items-app --disable all -o app.wasm
go-chatty/build.sh   # tinygo, go and wasm-tools on PATH
cd cs-chatty && dotnet build -c Release   # .NET 10 SDK
zig-chatty/build.sh
```

Then `appfuzz review` in each directory.

## What review finds

All seven: `n_plus_1` (calls to items#get grow as 1·n, cost breaks its limit
at n = 100), `over_budget` (129 cost), `chatty`, `redundant_calls`,
`serial_chain`, with the same titles.

Per language:

- **TypeScript** also fails `hang` / `over_budget` on fuel: with 32 items
  whose fields are 10 KB strings, the four regex `replace` calls in `esc`
  cost about 27M fuel per item in the JS engine (Rust: 9.9M fuel for all
  32), so the run hits the 200M limit.
- **JavaScript**: the same as TypeScript, the fuel `hang` included.
- **Go** also fails `ungranted_import` twice: the TinyGo runtime imports
  `wasi:filesystem`. It also goes over the fuel limit on long lists
  (`cpu_blowup`).
- **C#** also fails `ungranted_import` twice: the .NET runtime imports
  `wasi:filesystem`. It also warns `busy_wait`: the runtime reads the clock
  52 times in one request.
- **Python** also fails `ungranted_import` eight times: the
  componentize-py runtime imports `wasi:filesystem` and `wasi:sockets`
  whatever the app uses.
- **Zig** also fails `ungranted_import` twice: wasi-libc and the preview1
  adapter import `wasi:filesystem`. Zig's default WebAssembly stack is
  16 MB; with it, every fresh instance maps 17 MB and runs drop to 3,700/s.
  `build.sh` sets 1 MB, as Rust does. The rest of the gap to Rust is the
  adapter, a second module in every instance.
- **Worlds:** componentize-js and componentize-py import every interface of
  the world they are built against, so build against a world with only the
  imports the app uses (`items-app`), or appfuzz reports the rest as
  ungranted.

## What is weaker for interpreted languages

Coverage guidance sees the interpreter's branches, not the script's, and
static findings (`host_call_in_loop`, `wasm disasm`, `profile`) point at
interpreter functions. Each run boots the engine, so there are fewer runs per
second than for Rust.
