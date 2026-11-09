//! The page session: the event loop around the shim. Load the page, run
//! its scripts in a browser's order, fire DOMContentLoaded and load, let
//! timers run, act on every candidate, let time pass, report.
//!
//! The shim (`js/dist/shim.js`) owns the page's world: the DOM, timers on
//! virtual time, recorded requests. This side owns what QuickJS needs the
//! embedder for: classic and module scripts, the module loader, the
//! microtask queue and unhandled rejections.

use rquickjs::context::EvalOptions;
use rquickjs::function::IntoArgs;
use rquickjs::loader::{ImportAttributes, Loader, Resolver};
use rquickjs::module::Declared;
use rquickjs::{Context, Ctx, Error, FromJs, Function, IntoJs, Module, Object, Persistent, Result, Runtime, Value, qjs};

const SHIM: &str = include_str!("../../js/dist/shim.js");
const PARSER: &str = include_str!("../../js/dist/parser.js");

/// Virtual time the page gets after load, after each action, and at the
/// end, in milliseconds.
const AFTER_LOAD_MS: f64 = 1_000.0;
const AFTER_ACTION_MS: f64 = 500.0;
const AT_END_MS: f64 = 30_000.0;
/// Then 30 days pass, with timers fired at most once a day: what a page
/// does after a week (a time bomb) still shows, and a timer that ticks
/// all along costs 30 ticks.
const LATER_MS: f64 = 30.0 * 24.0 * 3_600_000.0;
const THROTTLE_MS: f64 = 24.0 * 3_600_000.0;
/// CPU (ms, as a browser counts it) the page may use in each of those two
/// waits. An ordinary page's timers use a fraction of it; a busy page is
/// cut off, and the share it used until then is still measured.
const WAIT_CPU_MS: f64 = 20.0;
/// CPU the page may use until its actions are done: a React app's whole
/// session uses about 6 ms. A page that uses more is cut off, so the
/// session's fuel still pays for the waits and the report.
const BUSY_CPU_MS: f64 = 60.0;
/// Tasks one settle may run: a page that keeps scheduling is cut off.
const MAX_STEPS: u32 = 10_000;
const MAX_ACTIONS: usize = 64;
const MAX_JOBS: u32 = 1_000_000;

fn call<'js, A: IntoArgs<'js>, R: FromJs<'js>>(ctx: &Ctx<'js>, name: &str, args: A) -> Result<R> {
    // The control handle lives in runtime userdata, outside the page's global
    // object. Recreated globals and getters cannot replace driver operations.
    let af = ctx.userdata::<Object>().ok_or(Error::Unknown)?;
    let f: Function = af.get(name)?;
    f.call(args)
}

/// Reports an error to the page's error list.
fn report<'js>(ctx: &Ctx<'js>, place: &str, e: Error) {
    let notify = e.is_exception();
    let v = if notify { ctx.catch() } else { e.to_string().into_js(ctx).unwrap_or(Value::new_undefined(ctx.clone())) };
    let _ = call::<_, ()>(ctx, "error", (place, v, notify));
}

/// Calls the shim, reporting a failure instead of returning it.
fn shim<'js, A: IntoArgs<'js>, R: FromJs<'js> + Default>(ctx: &Ctx<'js>, name: &str, args: A) -> R {
    match call(ctx, name, args) {
        Ok(r) => r,
        Err(e) => {
            report(ctx, &format!("driver:{name}"), e);
            R::default()
        }
    }
}

struct PageResolver;

impl Resolver for PageResolver {
    fn resolve<'js>(&mut self, ctx: &Ctx<'js>, base: &str, name: &str, _: Option<ImportAttributes<'js>>) -> Result<String> {
        call(ctx, "resolve", (name, base))
    }
}

struct PageLoader;

impl Loader for PageLoader {
    fn load<'js>(&mut self, ctx: &Ctx<'js>, name: &str, _: Option<ImportAttributes<'js>>) -> Result<Module<'js, Declared>> {
        match call::<_, Option<String>>(ctx, "file", (name,))? {
            Some(code) => {
                let module = Module::declare(ctx.clone(), name, code)?;
                module.meta()?.set("url", name)?;
                Ok(module)
            }
            None => Err(Error::new_loading_message(name, "no answer has this module")),
        }
    }
}

/// The private host bridge: the shim's `appfuzz:browser` imports.
/// Natively there is none and the shim answers requests from the session's
/// files and responses.
#[cfg(target_arch = "wasm32")]
mod bridge {
    use crate::component::{nav, net, sink};
    use rquickjs::convert::List;
    use rquickjs::function::Flat;
    use rquickjs::{Array, ArrayBuffer, Ctx, Function, Object, Result};

    /// Header pairs as JS arrays: rquickjs converts tuples through `List`.
    type Headers = Vec<List<(String, String)>>;
    type FetchAnswer = (u16, Vec<(String, String)>, Option<()>, Option<String>, Option<f64>);

    pub fn install<'js>(ctx: &Ctx<'js>) -> Result<Object<'js>> {
        let host = Object::new(ctx.clone())?;
        host.set("fetch", Function::new(ctx.clone(), fetch)?)?;
        host.set("go", Function::new(ctx.clone(), |how: String, url: String, gesture: bool| nav::go(&how, &url, gesture))?)?;
        host.set("html", Function::new(ctx.clone(), |at: String, value: String| sink::html(&at, &value))?)?;
        host.set("code", Function::new(ctx.clone(), |at: String, value: String| sink::code(&at, &value))?)?;
        Ok(host)
    }

    std::thread_local! {
        /// Host-clock time spent waiting for answers to requests.
        static WAITED_MS: std::cell::Cell<f64> = const { std::cell::Cell::new(0.0) };
    }

    /// A request: `target` is a path on the page's origin when `own`, else
    /// a URL. The answer is `[status, headers, body, error, latency_ms]`.
    fn fetch<'js>(
        Flat((ctx, kind)): Flat<(Ctx<'js>, String)>,
        method: String,
        own: bool,
        target: String,
        headers: Headers,
        body: Option<ArrayBuffer<'js>>,
        List((gesture, now_ms)): List<(bool, f64)>,
    ) -> Result<rquickjs::Value<'js>> {
        let headers: Vec<(String, String)> = headers.into_iter().map(|List(h)| h).collect();
        // SAFETY: copying the rooted buffer runs no JavaScript. The owned
        // bytes outlive this borrow before a nested app is invoked.
        let body = body.map(|buffer| unsafe { buffer.as_bytes() }.unwrap_or_default().to_vec());
        let before = host_ms();
        let answer = if own {
            net::fetch_own(&kind, &method, &target, &headers, body.as_deref(), gesture, now_ms.floor() as i64)
        } else {
            net::fetch_other(&kind, &method, &target, &headers, body.as_deref(), gesture)
        };
        let latency = host_ms().zip(before).map(|(after, before)| (after - before).max(0.0));
        if let Some(latency) = latency {
            WAITED_MS.with(|w| w.set(w.get() + latency));
        }
        let (answer, bytes): (FetchAnswer, Vec<u8>) = match answer {
            Ok(r) => ((r.status, r.headers, None, None, latency), r.body),
            Err(e) => ((0, Vec::new(), None, Some(e), latency), Vec::new()),
        };
        let value = crate::web::private_json(&ctx, serde_json::json!(answer))?;
        let array = Array::from_value(value)?;
        // Slot 2 already exists as a writable own data property. Updating it
        // cannot invoke an inherited array index setter from the page.
        array.set(2, ArrayBuffer::new_copy(ctx.clone(), &bytes)?)?;
        Ok(array.into_value())
    }

    /// The host's clock (appfuzz's virtual one) in ms, and a seed from its
    /// random source: read per session, never baked into the snapshot.
    pub fn host_ms() -> Option<f64> {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs_f64() * 1000.0)
    }

    /// The CPU the page has used so far, in ms: the host's clock counts the
    /// guest's work, and the waits for answers are taken out.
    pub fn cpu_ms() -> Option<f64> {
        host_ms().map(|t| t - WAITED_MS.with(std::cell::Cell::get))
    }

    pub fn now_and_seed() -> (Option<f64>, Option<f64>) {
        let now = host_ms().map(f64::floor);
        let mut b = [0u8; 4];
        let seed = getrandom::fill(&mut b).ok().map(|()| f64::from(u32::from_le_bytes(b)));
        (now, seed)
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod bridge {
    pub fn cpu_ms() -> Option<f64> {
        None
    }

    pub fn now_and_seed() -> (Option<f64>, Option<f64>) {
        (None, None)
    }
}

/// Phase times on stderr, natively, with `AF_TIMING` set.
struct Timer(#[cfg(not(target_arch = "wasm32"))] Option<std::time::Instant>);

impl Timer {
    fn new() -> Self {
        Timer(
            #[cfg(not(target_arch = "wasm32"))]
            std::env::var_os("AF_TIMING").map(|_| std::time::Instant::now()),
        )
    }

    fn mark(&mut self, _label: &str) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(t) = &mut self.0 {
            eprintln!("{_label}: {:.2} ms", t.elapsed().as_secs_f64() * 1000.0);
            *t = std::time::Instant::now();
        }
    }
}

/// Compiles without running: a module (registered under `url`, so imports
/// of it find it) or a classic script's code.
fn compile<'js>(ctx: &Ctx<'js>, url: &str, code: &str, module: bool) -> Option<Value<'js>> {
    let name = std::ffi::CString::new(url).ok()?;
    let src = std::ffi::CString::new(code).ok()?;
    let kind = if module { qjs::JS_EVAL_TYPE_MODULE | qjs::JS_EVAL_FLAG_STRICT } else { qjs::JS_EVAL_TYPE_GLOBAL };
    let flags = (kind | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as i32;
    // SAFETY: both strings are NUL-terminated; the result is an owned value.
    let v = unsafe { Value::from_raw(ctx.clone(), qjs::JS_Eval(ctx.as_raw().as_ptr(), src.as_ptr(), code.len() as qjs::size_t, name.as_ptr(), flags)) };
    if v.is_exception() {
        let _ = ctx.catch();
        return None;
    }
    if module {
        if unsafe { qjs::JS_VALUE_GET_TAG(v.as_raw()) } != qjs::JS_TAG_MODULE {
            return None;
        }
        // SAFETY: a successful module-only compile returns a rooted module
        // value. Its pointer remains valid while v is alive. Import metadata
        // is a fresh null-prototype object, independent of page prototypes.
        let meta = unsafe { Value::from_raw(ctx.clone(), qjs::JS_GetImportMeta(ctx.as_raw().as_ptr(), qjs::JS_VALUE_GET_PTR(v.as_raw()).cast())) };
        if meta.is_exception() {
            let _ = ctx.catch();
            return None;
        }
        meta.into_object()?.set("url", url).ok()?;
    }
    Some(v)
}

/// Runs what `compile` made: a module's evaluation promise, or a script's
/// completion value.
fn run_compiled<'js>(ctx: &Ctx<'js>, compiled: Value<'js>) -> Result<Value<'js>> {
    // SAFETY: JS_EvalFunction consumes one reference, so it gets a
    // duplicate; `compiled` drops its own (and its context's) as usual. A
    // module's count stays above zero: the context's module list holds one.
    // The result is an owned value.
    let v = unsafe {
        let raw = qjs::JS_DupValue(ctx.as_raw().as_ptr(), compiled.as_raw());
        Value::from_raw(ctx.clone(), qjs::JS_EvalFunction(ctx.as_raw().as_ptr(), raw))
    };
    if v.is_exception() { Err(Error::Exception) } else { Ok(v) }
}

type Compiled = std::collections::HashMap<(String, bool), Persistent<Value<'static>>>;

struct Page {
    // Dropped before the runtime it lives in.
    compiled: std::cell::RefCell<Compiled>,
    _parser_ctx: Context,
    rt: Runtime,
    ctx: Context,
}

/// A wait: the virtual time that passed, the CPU the page used in it
/// (none natively, without the host's clock), and whether the CPU cap
/// ended it early.
struct Wait {
    ms: f64,
    cpu_ms: Option<f64>,
    cut: bool,
}

impl Wait {
    fn json(&self) -> String {
        let cpu = self.cpu_ms.map_or("null".to_string(), |c| c.to_string());
        format!(r#"{{"ms":{},"cpu_ms":{cpu},"cut":{}}}"#, self.ms, self.cut)
    }
}

impl Page {
    /// Compiles an app's static scripts (`{"modules": {url: code},
    /// "classic": {url: code}}`) ahead of its sessions.
    fn precompile(&self, json: &str) {
        self.ctx.with(|ctx| {
            let Some(all) = ctx.json_parse(json).ok().and_then(Value::into_object) else { return };
            for (key, module) in [("modules", true), ("classic", false)] {
                let Ok(files) = all.get::<_, Object>(key) else { continue };
                for (url, code) in files.props::<String, String>().filter_map(std::result::Result::ok) {
                    if let Some(v) = compile(&ctx, &url, &code, module) {
                        self.compiled.borrow_mut().insert((url, module), Persistent::save(&ctx, v));
                    }
                }
            }
        });
    }

    /// The compiled form of a script, if the snapshot has it (once).
    fn take<'js>(&self, ctx: &Ctx<'js>, url: &str, module: bool) -> Option<Value<'js>> {
        let p = self.compiled.borrow_mut().remove(&(url.to_string(), module))?;
        p.restore(ctx).ok()
    }

    /// Runs microtasks until none is left, then the scripts the page
    /// created meanwhile.
    fn flush(&self) {
        let mut remaining = MAX_JOBS;
        loop {
            while remaining > 0 {
                remaining -= 1;
                match self.rt.execute_pending_job() {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => e.0.with(|ctx| {
                        let v = ctx.catch();
                        let _ = call::<_, ()>(&ctx, "error", ("job", v));
                    }),
                }
            }
            // Rejection listeners can queue more microtasks. Drain them
            // before returning to the next script or timer task.
            let notified: bool = self.ctx.with(|ctx| shim(&ctx, "checkpoint", ()));
            if !notified || remaining == 0 {
                break;
            }
        }
        let n: usize = self.ctx.with(|ctx| shim(&ctx, "newScripts", ()));
        if n > 0 {
            self.scripts(n);
        }
    }

    /// Alternate parser-blocking batches with tree building. Every script's
    /// microtask checkpoint runs before the parser reaches later elements.
    fn initial_scripts(&self, n: usize) {
        let mut batch = Some(n);
        while let Some(n) = batch {
            self.scripts(n);
            batch = self.ctx.with(|ctx| shim(&ctx, "resumeParser", ()));
        }
    }

    /// Runs the shim's current script list, flushing after each.
    fn scripts(&self, n: usize) {
        // Flushing may run a newly created batch. Keep this batch's
        // remaining nodes, rather than indexing the shim's replaced list.
        let Some(batch) = self.ctx.with(|ctx| shim::<_, Option<Object>>(&ctx, "scriptList", ()).map(|v| Persistent::save(&ctx, v))) else { return };
        for i in 0..n {
            self.ctx.with(|ctx| {
                let batch = match batch.clone().restore(&ctx) {
                    Ok(batch) => batch,
                    Err(e) => {
                        report(&ctx, "driver:scriptList", e);
                        return;
                    }
                };
                let Some(s) = shim::<_, Option<Object>>(&ctx, "scriptAt", (batch, i)) else { return };
                let kind: String = s.get("kind").unwrap_or_default();
                let url: String = s.get("url").unwrap_or_default();
                let inline: bool = s.get("inline").unwrap_or_default();
                if let Some(compiled) = (!inline).then(|| self.take(&ctx, &url, kind == "module")).flatten() {
                    let ok = match run_compiled(&ctx, compiled) {
                        Ok(v) => {
                            if kind == "module" {
                                shim::<_, ()>(&ctx, "watch", (v, url.clone()));
                            }
                            true
                        }
                        Err(e) => {
                            report(&ctx, &format!("{kind}:{url}"), e);
                            false
                        }
                    };
                    shim::<_, ()>(&ctx, "scriptDone", (ok,));
                    return;
                }
                let Some(code) = s.get::<_, Option<String>>("code").unwrap_or_default() else {
                    report(&ctx, &format!("script:{url}"), Error::new_loading_message(&url, "no answer has this script"));
                    shim::<_, ()>(&ctx, "scriptDone", (false,));
                    return;
                };
                let ok = if kind == "module" {
                    match Module::declare(ctx.clone(), url.clone(), code).and_then(|m| {
                        let meta_url = s.get::<_, Option<String>>("metaURL")?.unwrap_or_else(|| url.clone());
                        m.meta()?.set("url", meta_url)?;
                        m.eval()
                    }) {
                        Ok((_, promise)) => {
                            shim::<_, ()>(&ctx, "watch", (promise, url.clone()));
                            true
                        }
                        Err(e) => {
                            report(&ctx, &format!("module:{url}"), e);
                            false
                        }
                    }
                } else {
                    let mut opts = EvalOptions::default();
                    opts.strict = false;
                    opts.filename = Some(url.clone());
                    match ctx.eval_with_options::<(), _>(code, opts) {
                        Ok(()) => true,
                        Err(e) => {
                            report(&ctx, &format!("script:{url}"), e);
                            false
                        }
                    }
                };
                shim::<_, ()>(&ctx, "scriptDone", (ok,));
            });
            self.flush();
        }
    }

    /// Lets due tasks run for `ms` virtual milliseconds, or until they
    /// have used `cpu_ms` of CPU.
    fn wait(&self, ms: f64, cpu_ms: f64) -> Wait {
        let start: f64 = self.ctx.with(|ctx| shim(&ctx, "now", ()));
        let before = bridge::cpu_ms();
        let used = || bridge::cpu_ms().zip(before).map(|(a, b)| a - b);
        self.ctx.with(|ctx| shim::<_, ()>(&ctx, "until", (ms,)));
        let mut cut = cpu_ms <= 0.0;
        // (virtual time, CPU used before it) of the first and the last task.
        let (mut first, mut last) = (None, None);
        for _ in 0..if cut { 0 } else { MAX_STEPS } {
            let cpu = used();
            if !self.ctx.with(|ctx| shim::<_, bool>(&ctx, "step", ())) {
                break;
            }
            let t: f64 = self.ctx.with(|ctx| shim(&ctx, "now", ()));
            first.get_or_insert((t, cpu));
            last = Some((t, cpu));
            self.flush();
            if used().is_some_and(|u| u > cpu_ms) {
                cut = true;
                break;
            }
        }
        let at: f64 = self.ctx.with(|ctx| shim(&ctx, "now", ()));
        let next: f64 = self.ctx.with(|ctx| shim(&ctx, "next", ()));
        let total = used();
        self.ctx.with(|ctx| shim::<_, ()>(&ctx, "idle", ()));
        match (first, last) {
            // Cut short: the CPU from the first task on, over the time from
            // it to the next task. A timer's tick costs its CPU and lasts
            // until the next tick: one tick tells the share.
            (Some((t0, Some(c0))), _) if cut && next > t0 => Wait { ms: next - t0, cpu_ms: total.map(|c| c - c0), cut },
            // No task is due any more: from the first task to the last.
            (Some((t0, Some(c0))), Some((t1, Some(c1)))) if cut && t1 > t0 => Wait { ms: t1 - t0, cpu_ms: Some(c1 - c0), cut },
            _ => Wait { ms: if cut { at - start } else { ms }, cpu_ms: total, cut },
        }
    }

    fn ended(&self) -> bool {
        self.ctx.with(|ctx| shim(&ctx, "ended", ()))
    }
}

fn fail(ctx: &Ctx, e: Error) -> String {
    if e.is_exception() { format!("{:?}", ctx.catch()) } else { e.to_string() }
}

// Inline scripts created by DOM operations run before that operation
// returns. Use the callback's context directly, including for nested
// insertions, rather than reentering the Page runtime/context lock.
fn run_inline<'js>(ctx: Ctx<'js>, code: rquickjs::String<'js>, url: String) -> Result<()> {
    crate::web::compile_classic_script(ctx, code, url)?.call(())
}

// Callback cleanup for host-fired message listeners. Reenter the same context
// directly rather than taking the runtime lock while JavaScript is running.
fn message_checkpoint(ctx: Ctx<'_>) -> bool {
    for _ in 0..MAX_JOBS {
        let mut job_context = std::ptr::null_mut();
        // SAFETY: ctx is rooted and its runtime is exclusively executing on
        // this thread. QuickJS supports nested job execution; the returned
        // context is valid when a job reports an exception.
        let status = unsafe { qjs::JS_ExecutePendingJob(qjs::JS_GetRuntime(ctx.as_raw().as_ptr()), &mut job_context) };
        if status < 0 {
            if let Some(pointer) = std::ptr::NonNull::new(job_context) {
                // SAFETY: the job context belongs to this live runtime and
                // is used only within the callback's dynamic lifetime.
                let failed = unsafe { Ctx::from_raw(pointer) };
                report(&failed, "job", Error::Exception);
            }
        } else if status == 0 {
            return false;
        }
    }
    // SAFETY: the callback still owns the same live runtime. An exactly-full
    // checkpoint is complete if its final job emptied the queue.
    unsafe { qjs::JS_IsJobPending(qjs::JS_GetRuntime(ctx.as_raw().as_ptr())) }
}

/// A runtime with the shim loaded and no page yet.
fn boot() -> std::result::Result<Page, String> {
    let rt = Runtime::new().map_err(|e| format!("runtime: {e}"))?;
    rt.set_max_stack_size(1 << 20);
    rt.set_loader(PageResolver, PageLoader);
    rt.set_host_promise_rejection_tracker(Some(Box::new(|ctx, promise, reason, handled| {
        let _ = if handled { call::<_, ()>(&ctx, "handled", (promise,)) } else { call::<_, ()>(&ctx, "rejected", (promise, reason)) };
    })));
    let parser_ctx = Context::full(&rt).map_err(|e| format!("parser context: {e}"))?;
    let parser_factory = parser_ctx.with(|ctx| {
        ctx.eval::<(), _>(PARSER).map_err(|e| fail(&ctx, e))?;
        let factory: Function = ctx.globals().get("__appfuzzParser").map_err(|e| fail(&ctx, e))?;
        Ok::<_, String>(Persistent::save(&ctx, factory))
    })?;
    let ctx = Context::full(&rt).map_err(|e| format!("context: {e}"))?;
    ctx.with(|ctx| crate::web::install(&ctx).map_err(|e| fail(&ctx, e)))?;
    ctx.with(|ctx| {
        let native: Object = ctx.globals().get("__native").map_err(|e| fail(&ctx, e))?;
        native.set("htmlParser", parser_factory.restore(&ctx).map_err(|e| fail(&ctx, e))?).map_err(|e| fail(&ctx, e))
    })?;
    ctx.with(|ctx| {
        ctx.eval::<(), _>(SHIM).map_err(|e| fail(&ctx, e))?;
        let handle: Object = ctx.globals().get("__af").map_err(|e| fail(&ctx, e))?;
        ctx.store_userdata(handle).map_err(|_| "cannot store browser driver".to_string())?;
        Ok::<_, String>(())
    })?;
    ctx.with(|ctx| {
        let run = Function::new(ctx.clone(), run_inline).map_err(|e| fail(&ctx, e))?;
        call::<_, ()>(&ctx, "bindClassic", (run,)).map_err(|e| fail(&ctx, e))
    })?;
    ctx.with(|ctx| {
        let checkpoint = Function::new(ctx.clone(), message_checkpoint).map_err(|e| fail(&ctx, e))?;
        call::<_, ()>(&ctx, "bindMessageCheckpoint", (checkpoint,)).map_err(|e| fail(&ctx, e))
    })?;
    #[cfg(target_arch = "wasm32")]
    ctx.with(|ctx| {
        let host = bridge::install(&ctx).map_err(|e| fail(&ctx, e))?;
        call::<_, ()>(&ctx, "bindHost", (host,)).map_err(|e| fail(&ctx, e))
    })?;
    ctx.with(|ctx| {
        for name in ["__af", "__native"] {
            ctx.globals().remove(name).map_err(|e| fail(&ctx, e))?;
        }
        Ok::<_, String>(())
    })?;
    Ok(Page { compiled: Default::default(), _parser_ctx: parser_ctx, rt, ctx })
}

thread_local! {
    static BOOTED: std::cell::RefCell<Option<Page>> = const { std::cell::RefCell::new(None) };
}

/// Boots ahead of the first session. A snapshot taken after this (wizer)
/// starts every session with the shim already evaluated, and with the
/// scripts on stdin (an app's static scripts) already compiled.
pub fn initialize() {
    // A snapshot without a working browser would fail every session. Surface
    // boot failures during the build instead of silently snapshotting None.
    let page = boot().unwrap_or_else(|message| panic!("browser boot failed: {message}"));
    let scripts = std::io::read_to_string(std::io::stdin()).unwrap_or_default();
    if !scripts.is_empty() {
        page.precompile(&scripts);
    }
    BOOTED.with(|b| *b.borrow_mut() = Some(page));
}

/// One page session. `input` is JSON: `{url, html, files, responses,
/// cookies, now, seed}`; the result is the shim's report.
pub fn session(input: &str) -> String {
    let mut timer = Timer::new();
    let page = match BOOTED.with(|b| b.borrow_mut().take()).map_or_else(boot, Ok) {
        Ok(page) => page,
        Err(e) => return format!(r#"{{"fatal":{e:?}}}"#),
    };
    timer.mark("boot");
    let (now, seed) = bridge::now_and_seed();
    let start = bridge::cpu_ms();
    let busy_left = || start.zip(bridge::cpu_ms()).map_or(f64::INFINITY, |(s, n)| BUSY_CPU_MS - (n - s));
    let n = match page.ctx.with(|ctx| call::<_, usize>(&ctx, "init", (input, now, seed)).map_err(|e| fail(&ctx, e))) {
        Ok(n) => n,
        Err(e) => return format!(r#"{{"fatal":{e:?}}}"#),
    };
    timer.mark("init");
    page.initial_scripts(n);
    timer.mark("scripts");
    page.ctx.with(|ctx| shim::<_, ()>(&ctx, "ready", ()));
    page.flush();
    page.ctx.with(|ctx| shim::<_, ()>(&ctx, "loaded", ()));
    page.flush();
    let mut busy_cut = page.wait(AFTER_LOAD_MS, busy_left()).cut;
    timer.mark("load");
    // Every candidate once, in document order; candidates are counted
    // again after each action, since actions change the page.
    let mut i = 0;
    while i < MAX_ACTIONS && !page.ended() && !busy_cut {
        let count: usize = page.ctx.with(|ctx| shim(&ctx, "count", ()));
        if i >= count {
            break;
        }
        page.ctx.with(|ctx| shim::<_, bool>(&ctx, "act", (i, Value::new_undefined(ctx.clone()))));
        page.flush();
        busy_cut = page.wait(AFTER_ACTION_MS, busy_left()).cut;
        i += 1;
    }
    timer.mark("actions");
    let busy = start.zip(bridge::cpu_ms()).map_or("null".to_string(), |(s, n)| (n - s).to_string());
    // The CPU the page's timers use while it sits idle, then while days pass.
    let idle = page.wait(AT_END_MS, WAIT_CPU_MS);
    page.ctx.with(|ctx| shim::<_, ()>(&ctx, "throttle", (THROTTLE_MS,)));
    let later = page.wait(LATER_MS, WAIT_CPU_MS);
    let mut out = page.ctx.with(|ctx| shim::<_, String>(&ctx, "report", ()));
    if let Some(end) = out.rfind('}') {
        out.insert_str(end, &format!(r#","busy":{{"cpu_ms":{busy},"cut":{busy_cut}}},"idle":{},"later":{}"#, idle.json(), later.json()));
    }
    timer.mark("end+report");
    // The instance ends with the session: freeing the page's heap object
    // by object would only cost fuel (about 5% of a React session).
    #[cfg(target_arch = "wasm32")]
    std::mem::forget(page);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_listener_objects(script: &str) -> i64 {
        let page = boot().unwrap();
        page.ctx.with(|ctx| {
            call::<_, usize>(&ctx, "init", (r#"{"url":"https://app.example/","html":"<body></body>"}"#, 0.0, 1_u32)).unwrap();
        });
        page.rt.run_gc();
        let before = page.rt.memory_usage().obj_count;
        page.ctx.with(|ctx| ctx.eval::<(), _>(script).unwrap());
        page.rt.run_gc();
        page.rt.memory_usage().obj_count - before
    }

    #[test]
    fn detached_listened_nodes_are_collectible() {
        let retained = retained_listener_objects("for(let i=0;i<256;i++){const node=document.createElement('div');node.addEventListener('click',()=>{});}");
        assert!(retained < 128, "detached listener objects retained: {retained}");
    }

    #[test]
    fn closed_listened_ports_are_collectible() {
        let retained = retained_listener_objects(
            "for(let i=0;i<256;i++){const channel=new MessageChannel();channel.port1.onmessage=()=>{};channel.port2.onmessage=()=>{};channel.port1.close();channel.port2.close();}",
        );
        assert!(retained < 128, "closed port objects retained: {retained}");
    }

    #[test]
    fn controller_discovery_does_not_call_array_index_setters() {
        let out = session(
            r#"{"url":"https://app.example/","html":"<button type=button>tap</button><script>const define=Object.defineProperty;let calls=0;document.querySelector('button').addEventListener('click',()=>console.log('clicked'));define(Array.prototype,'0',{configurable:true,set(value){define(this,'0',{value,writable:true,enumerable:true,configurable:true});calls++}});setTimeout(()=>console.log('callbacks',calls),2000)</script>"}"#,
        );
        assert!(out.contains(r#""text":"clicked""#), "{out}");
        assert!(out.contains(r#""text":"callbacks 0""#), "{out}");
        assert!(out.contains(r#""errors":[]"#), "{out}");
    }

    #[test]
    fn private_driver_survives_recreated_globals_and_report_serializers() {
        for _ in 0..3 {
            let out = session(
                r#"{"url":"https://app.example/","html":"<script>globalThis.__af={};Object.prototype.toJSON=()=>({});JSON.stringify=()=>'';console.log('sentinel')</script>"}"#,
            );
            assert!(out.contains(r#""url":"https://app.example/""#), "{out}");
            assert!(out.contains(r#""text":"sentinel""#), "{out}");
        }
    }

    #[test]
    fn module_metadata_and_imports_use_the_preparation_base() {
        let out = session(
            r#"{"url":"https://app.example/index.html","html":"<base href='/nested/'><script type=module>import './dep.mjs';console.log('inline',import.meta.url)</script>","files":{"/nested/dep.mjs":"console.log('dependency',import.meta.url,Object.getPrototypeOf(import.meta)===null)"}}"#,
        );
        assert!(out.contains(r#""text":"inline https://app.example/nested/""#), "{out}");
        assert!(out.contains(r#""text":"dependency https://app.example/nested/dep.mjs true""#), "{out}");
        assert!(out.contains(r#""errors":[]"#), "{out}");
    }

    #[test]
    fn external_module_metadata_does_not_invoke_object_prototype_setters() {
        let out = session(
            r#"{"url":"https://app.example/","html":"<script>Object.defineProperty(Object.prototype,'url',{set(){throw Error('author url')},configurable:true})</script><script type=module src='/entry.mjs'></script>","files":{"/entry.mjs":"console.log('external',import.meta.url,Object.getPrototypeOf(import.meta)===null)"}}"#,
        );
        assert!(out.contains(r#""text":"external https://app.example/entry.mjs true""#), "{out}");
        assert!(out.contains(r#""errors":[]"#), "{out}");
    }

    #[test]
    fn precompiled_modules_initialize_their_import_metadata() {
        let page = boot().unwrap();
        page.precompile(
            r#"{"modules":{"https://app.example/precompiled.mjs":"console.log('compiled',import.meta.url,Object.getPrototypeOf(import.meta)===null)"}}"#,
        );
        BOOTED.with(|slot| *slot.borrow_mut() = Some(page));
        let out = session(
            r#"{"url":"https://app.example/","html":"<script type=module src='/precompiled.mjs'></script>","files":{"/precompiled.mjs":"throw Error('should use compiled code')"}}"#,
        );
        assert!(out.contains(r#""text":"compiled https://app.example/precompiled.mjs true""#), "{out}");
        assert!(out.contains(r#""errors":[]"#), "{out}");
    }

    #[test]
    fn module_loader_uses_the_private_driver_after_page_globals_change() {
        let out = session(
            r#"{"url":"https://app.example/","html":"<script>globalThis.__af={};</script><script type=module>import {value} from '/module.js';console.log(value)</script>","files":{"/module.js":"export const value='module sentinel'"}}"#,
        );
        assert!(out.contains(r#""text":"module sentinel""#), "{out}");
        assert!(out.contains(r#""errors":[]"#), "{out}");
    }
}
