//! wasi:http 0.2 in a run.
//!
//! wasmtime-wasi-http provides the resources (requests, responses, fields,
//! bodies). appfuzz shadows the few functions where data leaves the guest:
//!
//! - `outgoing-request.body`, `outgoing-response.body` and
//!   `outgoing-body.write`: bodies are written into a plain buffer that never
//!   blocks (wasmtime's channel blocks the guest when nobody drains it, and a
//!   drain task would make runs depend on thread timing).
//! - `outgoing-handler.handle` only records the request. The simulated host
//!   call happens when the guest first looks at the response
//!   (`future-incoming-response.subscribe` or `.get`), because SDKs (wstd,
//!   Spin) write the request body after `handle`. A request the guest never
//!   waits for is sent when the handler returns. Either way the order of host
//!   calls follows the guest, so runs stay deterministic.
//! - `response-outparam.set`: notes which body is the response's.
//! - `outgoing-request.set-authority`: also takes a host with a canary in it.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use wasmtime::component::{Func, Linker, Resource, Val};
use wasmtime::{AsContextMut, Store, StoreContextMut};
use wasmtime_wasi::p2::{DynOutputStream, OutputStream, Pollable, StreamError, StreamResult};
use wasmtime_wasi_http::p2::bindings::http::types as wt;
use wasmtime_wasi_http::p2::body::{HostOutgoingBody, HyperOutgoingBody, StreamContext};
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, HostIncomingRequest, HostOutgoingRequest, HostOutgoingResponse, HostResponseOutparam};
use wasmtime_wasi_http::{RequestOptions, WasiBody, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView};

use super::{Host, intercept};
use crate::value::{json_to_val, val_to_json};
use crate::wasi_http::CLIENT_KEY;

/// The wasi:http version wasmtime-wasi-http 50 provides. Shadowing under it
/// covers older 0.2.x imports through semver matching.
const VERSION: &str = "0.2.12";
/// The most one body may hold. A guest can write the same buffer forever;
/// host memory is not fuel.
const MAX_BODY: usize = 64 << 20;
/// What one write may carry (`check-write`).
const WRITE_BUDGET: usize = 64 << 10;

type Buffer = Arc<Mutex<Vec<u8>>>;
type Response = Result<http::Response<HyperOutgoingBody>, wt::ErrorCode>;

pub(super) struct Http {
    ctx: WasiHttpCtx,
    hooks: Hooks,
    /// The buffer of each outgoing body, by the body's resource.
    bodies: BTreeMap<u32, Buffer>,
    /// The buffer of each outgoing request's and response's body.
    requests: BTreeMap<u32, Buffer>,
    responses: BTreeMap<u32, Buffer>,
    /// Requests sent but not yet answered, by their future's resource.
    pending: BTreeMap<u32, Pending>,
    sent: u64,
    /// What the handler set as its response, and that response's body.
    response: Arc<Mutex<Option<Response>>>,
    response_body: Option<Buffer>,
    /// The handler's response as the run's result: a string body for text,
    /// a list of bytes otherwise, and trailers if any.
    pub(super) result: Option<Value>,
}

impl Default for Http {
    fn default() -> Self {
        Http {
            ctx: WasiHttpCtx::new(),
            hooks: Hooks,
            bodies: BTreeMap::new(),
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            pending: BTreeMap::new(),
            sent: 0,
            response: Arc::default(),
            response_body: None,
            result: None,
        }
    }
}

struct Pending {
    seq: u64,
    /// Virtual time when the guest sent it.
    sent_ns: u64,
    /// How long the guest lets it take: connect plus first-byte timeout.
    deadline_ns: Option<u64>,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<(HyperOutgoingBody, Buffer)>,
}

struct Hooks;

impl WasiHttpHooks for Hooks {
    /// Never used: `handle` is shadowed.
    fn send_request(
        &mut self,
        _request: http::Request<WasiBody>,
        _options: Option<RequestOptions>,
        _fut: Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send>,
    ) -> Box<dyn Future<Output = wasmtime_wasi_http::Result<(http::Response<WasiBody>, Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send>)>> + Send>
    {
        Box::new(async { Err(wasmtime_wasi_http::Error::InternalError(Some("appfuzz simulates outbound requests".into()))) })
    }
}

impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView { hooks: &mut self.http.hooks, table: &mut self.table, ctx: &mut self.http.ctx }
    }
}

/// An outgoing body's stream: appends to the buffer, never blocks.
struct BufferStream(Buffer);

#[async_trait::async_trait]
impl Pollable for BufferStream {
    async fn ready(&mut self) {}
}

impl OutputStream for BufferStream {
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        let mut b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if b.len() + bytes.len() > MAX_BODY {
            return Err(StreamError::Trap(wasmtime::format_err!("an HTTP body over {} MiB", MAX_BODY >> 20)));
        }
        b.extend_from_slice(&bytes);
        Ok(())
    }
    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }
    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(WRITE_BUDGET)
    }
}

/// How the guest ended a body.
#[derive(PartialEq)]
enum End {
    Finished,
    /// Finished with trailers.
    Trailers(http::HeaderMap),
    /// Still open: the guest holds the body.
    Open,
    Aborted,
}

/// Reads the end of a body without waiting. The data went to the buffer;
/// the channel only carries `finish` or an abort.
fn end_of(body: &mut HyperOutgoingBody) -> End {
    loop {
        let frame = std::pin::pin!(body.frame());
        match wasmtime_wasi::runtime::poll_noop(frame) {
            None => return End::Open,
            Some(None) => return End::Finished,
            Some(Some(Err(_))) => return End::Aborted,
            // Trailers end the body; data frames cannot come (the stream was replaced).
            Some(Some(Ok(f))) if f.is_trailers() => return f.into_trailers().map_or(End::Finished, End::Trailers),
            Some(Some(Ok(_))) => {}
        }
    }
}

fn contents(b: &Buffer) -> Vec<u8> {
    b.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub(super) fn link(linker: &mut Linker<Host>) -> Result<()> {
    wasmtime_wasi_http::p2::add_only_http_to_linker_sync(linker)?;
    let mut types = linker.instance(&format!("wasi:http/types@{VERSION}"))?;
    types.func_wrap("[method]outgoing-request.body", |mut store: StoreContextMut<'_, Host>, (req,): (Resource<HostOutgoingRequest>,)| {
        let host = store.data_mut();
        let (body, hyper) = HostOutgoingBody::new(StreamContext::Request, None, 1, WRITE_BUDGET);
        let r = host.table.get_mut(&req)?;
        if r.body.is_some() {
            return Ok((Err(()),));
        }
        r.body = Some(hyper);
        let id = host.table.push(body)?;
        let buf = Buffer::default();
        host.http.bodies.insert(id.rep(), buf.clone());
        host.http.requests.insert(req.rep(), buf);
        Ok((Ok(id),))
    })?;
    types.func_wrap("[method]outgoing-response.body", |mut store: StoreContextMut<'_, Host>, (resp,): (Resource<HostOutgoingResponse>,)| {
        let host = store.data_mut();
        let (body, hyper) = HostOutgoingBody::new(StreamContext::Response, None, 1, WRITE_BUDGET);
        let r = host.table.get_mut(&resp)?;
        if r.body.is_some() {
            return Ok((Err(()),));
        }
        r.body = Some(hyper);
        let id = host.table.push(body)?;
        let buf = Buffer::default();
        host.http.bodies.insert(id.rep(), buf.clone());
        host.http.responses.insert(resp.rep(), buf);
        Ok((Ok(id),))
    })?;
    types.func_wrap("[method]outgoing-body.write", |mut store: StoreContextMut<'_, Host>, (id,): (Resource<HostOutgoingBody>,)| {
        let host = store.data_mut();
        let body = host.table.get_mut(&id)?;
        // wasmtime's own stream; dropping it leaves the channel for `finish`.
        if body.take_output_stream().is_none() {
            return Ok((Err(()),));
        }
        let buf = host.http.bodies.get(&id.rep()).cloned().unwrap_or_default();
        let stream: DynOutputStream = Box::new(BufferStream(buf));
        Ok((Ok(host.table.push_child(stream, &id)?),))
    })?;
    types.func_wrap(
        "[static]response-outparam.set",
        |mut store: StoreContextMut<'_, Host>, (param, resp): (Resource<HostResponseOutparam>, Result<Resource<HostOutgoingResponse>, wt::ErrorCode>)| {
            let host = store.data_mut();
            if let Ok(r) = &resp {
                let has_body = host.table.get(r)?.body.is_some();
                host.http.response_body = if has_body { host.http.responses.get(&r.rep()).cloned() } else { None };
            }
            let mut view = host.http();
            wt::HostResponseOutparam::set(&mut view, param, resp)?;
            Ok(())
        },
    )?;
    // An attacker would name a valid host. appfuzz's canaries carry markup
    // and quotes, which no authority allows; accepted anyway, so a canary
    // that reaches the host part of a request shows as SSRF.
    types.func_wrap(
        "[method]outgoing-request.set-authority",
        |mut store: StoreContextMut<'_, Host>, (id, authority): (Resource<HostOutgoingRequest>, Option<String>)| {
            let rep = id.rep();
            let mut view = store.data_mut().http();
            let set = wt::HostOutgoingRequest::set_authority(&mut view, id, authority.clone())?;
            if set.is_err()
                && let Some(a) = authority.filter(|a| crate::output::CANARY.is_match(a))
            {
                store.data_mut().table.get_mut(&Resource::<HostOutgoingRequest>::new_borrow(rep))?.authority = Some(a);
                return Ok((Ok(()),));
            }
            Ok((set,))
        },
    )?;
    // The same for a path: an attacker sends `../admin`, which the types
    // accept; the canary's markup they would reject.
    types.func_wrap(
        "[method]outgoing-request.set-path-with-query",
        |mut store: StoreContextMut<'_, Host>, (id, path): (Resource<HostOutgoingRequest>, Option<String>)| {
            let rep = id.rep();
            let mut view = store.data_mut().http();
            let set = wt::HostOutgoingRequest::set_path_with_query(&mut view, id, path.clone())?;
            if set.is_err()
                && let Some(p) = path.filter(|p| crate::output::CANARY.is_match(p))
            {
                store.data_mut().table.get_mut(&Resource::<HostOutgoingRequest>::new_borrow(rep))?.path_with_query = Some(p);
                return Ok((Ok(()),));
            }
            Ok((set,))
        },
    )?;
    types.func_wrap("[method]future-incoming-response.subscribe", |mut store: StoreContextMut<'_, Host>, (id,): (Resource<HostFutureIncomingResponse>,)| {
        answer(&mut store, id.rep())?;
        let mut view = store.data_mut().http();
        Ok((wt::HostFutureIncomingResponse::subscribe(&mut view, id)?,))
    })?;
    types.func_wrap("[method]future-incoming-response.get", |mut store: StoreContextMut<'_, Host>, (id,): (Resource<HostFutureIncomingResponse>,)| {
        answer(&mut store, id.rep())?;
        let mut view = store.data_mut().http();
        Ok((wt::HostFutureIncomingResponse::get(&mut view, id)?,))
    })?;

    let mut out = linker.instance(&format!("wasi:http/outgoing-handler@{VERSION}"))?;
    out.func_wrap("handle", |mut store: StoreContextMut<'_, Host>, (req, options): (Resource<HostOutgoingRequest>, Option<Resource<RequestOptions>>)| {
        // The response must start within connect + first-byte timeout; a
        // connect timeout alone says nothing about a whole response.
        let deadline_ns = match options {
            Some(o) => {
                let o = store.data_mut().table.delete(o)?;
                o.first_byte_timeout.map(|f| (f + o.connect_timeout.unwrap_or_default()).as_nanos() as u64)
            }
            None => None,
        };
        Ok((send(&mut store, req, deadline_ns)?,))
    })?;
    Ok(())
}

/// `outgoing-handler.handle`: checks the request like the real host and
/// keeps it until the guest asks for the response.
fn send(
    store: &mut StoreContextMut<'_, Host>,
    id: Resource<HostOutgoingRequest>,
    deadline_ns: Option<u64>,
) -> wasmtime::Result<Result<Resource<HostFutureIncomingResponse>, wt::ErrorCode>> {
    let rep = id.rep();
    Host::sync_guest_time(store);
    let sent_ns = store.data().clock.with(|c| c.elapsed_ns());
    let host = store.data_mut();
    let req = host.table.delete(id)?;
    let buffer = host.http.requests.remove(&rep);
    let method = match &req.method {
        wt::Method::Get => "GET".to_string(),
        wt::Method::Head => "HEAD".into(),
        wt::Method::Post => "POST".into(),
        wt::Method::Put => "PUT".into(),
        wt::Method::Delete => "DELETE".into(),
        wt::Method::Connect => "CONNECT".into(),
        wt::Method::Options => "OPTIONS".into(),
        wt::Method::Trace => "TRACE".into(),
        wt::Method::Patch => "PATCH".into(),
        wt::Method::Other(m) if http::Method::from_bytes(m.as_bytes()).is_ok() => m.clone(),
        wt::Method::Other(_) => return Ok(Err(wt::ErrorCode::HttpRequestMethodInvalid)),
    };
    let scheme = match &req.scheme {
        None | Some(wt::Scheme::Https) => "https",
        Some(wt::Scheme::Http) => "http",
        Some(wt::Scheme::Other(_)) => return Ok(Err(wt::ErrorCode::HttpProtocolError)),
    };
    let authority = req.authority.clone().unwrap_or_default();
    if authority.is_empty() {
        return Ok(Err(wt::ErrorCode::HttpRequestUriInvalid));
    }
    let path = req.path_with_query.clone().unwrap_or_else(|| "/".into());
    let headers =
        http::HeaderMap::from(req.headers).iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    host.http.sent += 1;
    let pending = Pending {
        seq: host.http.sent,
        sent_ns,
        deadline_ns,
        method,
        url: format!("{scheme}://{authority}{path}"),
        headers,
        body: req.body.map(|b| (b, buffer.unwrap_or_default())),
    };
    let placeholder = Err(wasmtime_wasi_http::Error::InternalError(Some("not answered yet".into())));
    let future = host.table.push(HostFutureIncomingResponse::Ready(placeholder))?;
    // A reused slot: the guest dropped that earlier future without asking.
    if let Some(old) = host.http.pending.remove(&future.rep()) {
        resolve(store, None, old)?;
    }
    store.data_mut().http.pending.insert(future.rep(), pending);
    Ok(Ok(future))
}

/// Answers a pending request before the guest looks at its response.
fn answer(store: &mut StoreContextMut<'_, Host>, rep: u32) -> wasmtime::Result<()> {
    if let Some(p) = store.data_mut().http.pending.remove(&rep) {
        resolve(store, Some(rep), p)?;
    }
    Ok(())
}

/// Sends the requests the guest never waited for, in the order it sent them.
pub(super) fn flush(store: &mut Store<Host>) -> wasmtime::Result<()> {
    let mut pending: Vec<_> = std::mem::take(&mut store.data_mut().http.pending).into_iter().collect();
    pending.sort_by_key(|(_, p)| p.seq);
    for (rep, p) in pending {
        resolve(&mut store.as_context_mut(), Some(rep), p)?;
    }
    Ok(())
}

/// The simulated host call of one request; the answer goes into the future.
fn resolve(store: &mut StoreContextMut<'_, Host>, future: Option<u32>, p: Pending) -> wasmtime::Result<()> {
    let (body, end) = match p.body {
        None => (vec![], End::Finished),
        Some((mut hyper, buf)) => {
            let end = end_of(&mut hyper);
            (contents(&buf), end)
        }
    };
    let result = if end == End::Aborted {
        // The guest gave up on the body: the request never completes.
        Err(wasmtime_wasi_http::Error::HttpProtocolError)
    } else {
        let ty = store.data().platform.funcs.get(CLIENT_KEY).map(|f| f.ty.clone()).ok_or_else(|| wasmtime::format_err!("{CLIENT_KEY} is not linked"))?;
        let headers: Vec<Value> = p.headers.iter().map(|(k, v)| json!([k, v])).collect();
        let args = [json!(p.method), json!(p.url), Value::Array(headers), json!(String::from_utf8_lossy(&body))];
        let params = ty.params().zip(args.iter()).map(|((_, t), v)| json_to_val(v, &t)).collect::<Result<Vec<_>>>().map_err(wasmtime::Error::from_anyhow)?;
        let mut results = vec![Val::Bool(false)];
        store.data_mut().call_started_ns = Some(p.sent_ns);
        store.data_mut().call_deadline_ns = p.deadline_ns;
        intercept(store.as_context_mut(), CLIENT_KEY, &params, &mut results).map_err(wasmtime::Error::from_anyhow)?;
        match incoming(&val_to_json(&results[0])) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{CLIENT_KEY}: {e:#}");
                store.data_mut().plan_error = Some(msg.clone());
                return Err(wasmtime::format_err!(msg));
            }
        }
    };
    if let Some(rep) = future
        && let Ok(slot) = store.data_mut().table.get_mut(&Resource::<HostFutureIncomingResponse>::new_own(rep))
    {
        *slot = HostFutureIncomingResponse::Ready(result);
    }
    Ok(())
}

type SendResult = wasmtime_wasi_http::Result<(http::Response<WasiBody>, wasmtime_wasi::runtime::AbortOnDropJoinHandle<()>)>;

/// The host call's answer as the response the guest reads.
fn incoming(v: &Value) -> Result<SendResult> {
    if let Some(e) = v.get("err") {
        return Ok(Err(error_of(e.as_str().unwrap_or_default())));
    }
    let ok = v.get("ok").ok_or_else(|| anyhow!("not a result: {v}"))?;
    let status = ok.get("status").and_then(Value::as_u64).unwrap_or(0);
    let status = u16::try_from(status).ok().and_then(|s| http::StatusCode::from_u16(s).ok()).ok_or_else(|| anyhow!("{status} is not an HTTP status"))?;
    let mut builder = http::Response::builder().status(status);
    for (k, v) in pairs(ok.get("headers")) {
        // A real response cannot carry these; generated ones are skipped.
        if let (Ok(k), Ok(v)) = (http::HeaderName::from_bytes(k.as_bytes()), http::HeaderValue::from_str(&v)) {
            builder = builder.header(k, v);
        }
    }
    let body = ok.get("body").and_then(Value::as_str).unwrap_or_default().to_string();
    let body = Full::new(Bytes::from(body)).map_err(|e: Infallible| -> wasmtime_wasi_http::Error { match e {} }).boxed_unsync();
    let response = builder.body(body).context("response")?;
    Ok(Ok((response, wasmtime_wasi::runtime::spawn(async {}))))
}

fn pairs(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect())
        .unwrap_or_default()
}

/// A host error text as the guest's error code: `connection-refused`,
/// `connection-timeout`, `dns-timeout`, … or an internal error.
fn error_of(text: &str) -> wasmtime_wasi_http::Error {
    use wasmtime_wasi_http::Error as E;
    match text {
        "dns-timeout" => E::DnsTimeout,
        "destination-not-found" => E::DestinationNotFound,
        "destination-unavailable" => E::DestinationUnavailable,
        "connection-refused" => E::ConnectionRefused,
        "connection-terminated" => E::ConnectionTerminated,
        "connection-timeout" => E::ConnectionTimeout,
        "connection-read-timeout" => E::ConnectionReadTimeout,
        "connection-limit-reached" => E::ConnectionLimitReached,
        "tls-certificate-error" => E::TlsCertificateError,
        "http-request-denied" => E::HttpRequestDenied,
        "http-response-incomplete" => E::HttpResponseIncomplete,
        "http-response-timeout" => E::HttpResponseTimeout,
        other => E::InternalError(Some(other.to_string())),
    }
}

/// The request target as the platform's HTTP stack would hand it over.
/// An attacker sends raw bytes, not what a browser would encode: `'`, `(`,
/// `../` and the like arrive as they are. Only bytes the server's parser
/// rejects (spaces, controls, `"`, `<`, `>`, …) are percent-encoded, as a
/// client must to be heard at all. Text without `http(s)://` is a path on
/// the app's host.
fn deliver_uri(text: &str) -> Option<http::Uri> {
    use std::sync::LazyLock;
    // Which ASCII bytes the `http` crate accepts in a path and in a query.
    static OK: LazyLock<[[bool; 128]; 2]> = LazyLock::new(|| {
        let mut ok = [[false; 128]; 2];
        for b in 0u8..128 {
            let c = b as char;
            ok[0][b as usize] = matches!(c, '?' | '#') || http::uri::PathAndQuery::try_from(format!("/{c}")).is_ok();
            ok[1][b as usize] = c == '#' || http::uri::PathAndQuery::try_from(format!("/?{c}")).is_ok();
        }
        ok
    });
    let (origin, rest) = match text.find("://") {
        Some(i) if matches!(&text[..i], "http" | "https") => {
            let after = &text[i + 3..];
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            (&text[..i + 3 + end], &text[i + 3 + end..])
        }
        _ => ("", text),
    };
    let mut target = String::with_capacity(rest.len() + 1);
    if !rest.starts_with('/') {
        target.push('/');
    }
    let mut query = false;
    for c in rest.chars() {
        let keep = (c as u32) >= 128 || OK[query as usize][c as usize];
        if keep {
            target.push(c);
        } else {
            for b in c.to_string().bytes() {
                target.push_str(&format!("%{b:02X}"));
            }
        }
        query |= c == '?';
    }
    let uri: Option<http::Uri> = format!("{origin}{target}").parse().ok();
    uri.or_else(|| {
        // An authority the parser rejects: deliver the target on the app's host.
        target.parse().ok()
    })
}

/// Calls `wasi:http/incoming-handler#handle` with the request record and
/// returns the response record. The outer error is appfuzz's (a request
/// the platform would not deliver), the inner one the guest's.
pub(super) fn call_handler(store: &mut Store<Host>, func: Func, request: &Value) -> Result<std::result::Result<Value, wasmtime::Error>> {
    let text = |k: &str| request.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let method = text("method");
    let method = http::Method::from_bytes(method.as_bytes()).map_err(|_| anyhow!("the platform does not deliver method {method:?}"))?;
    let uri_text = text("uri");
    let uri = deliver_uri(&uri_text).ok_or_else(|| anyhow!("the platform does not deliver uri {uri_text:?}"))?;
    let scheme = match uri.scheme_str() {
        Some("https") => wt::Scheme::Https,
        Some("http") | None => wt::Scheme::Http,
        Some(other) => wt::Scheme::Other(other.to_string()),
    };
    let mut builder = http::Request::builder().method(method).uri(uri.clone());
    let headers = pairs(request.get("headers"));
    for (k, v) in &headers {
        // The platform's HTTP parser would reject these.
        if let (Ok(k), Ok(v)) = (http::HeaderName::from_bytes(k.as_bytes()), http::HeaderValue::from_str(v)) {
            builder = builder.header(k, v);
        }
    }
    if uri.authority().is_none() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        builder = builder.header(http::header::HOST, "app.example");
    }
    let body = Full::new(Bytes::from(text("body"))).map_err(|e: Infallible| -> wasmtime_wasi_http::Error { match e {} });
    let req = builder.body(body).context("request")?;

    let slot = store.data().http.response.clone();
    let (req, out) = {
        let mut view = store.data_mut().http();
        let req = view.new_incoming_request(scheme, req).map_err(anyhow::Error::from)?;
        let out = view.new_response_outparam_from_callback(move |r| *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(r)).map_err(anyhow::Error::from)?;
        (req, out)
    };
    let typed = func.typed::<(Resource<HostIncomingRequest>, Resource<HostResponseOutparam>), ()>(&*store).map_err(anyhow::Error::from)?;
    if let Err(e) = typed.call(&mut *store, (req, out)) {
        // Requests sent before the crash still went out.
        let _ = flush(store);
        return Ok(Err(e));
    }
    if let Err(e) = flush(store) {
        return Ok(Err(e));
    }
    let taken = store.data().http.response.lock().unwrap_or_else(|e| e.into_inner()).take();
    let response = match taken {
        None => return Ok(Err(wasmtime::format_err!("the handler returned without setting a response (response-outparam.set)"))),
        // The guest reports an error: the client gets a 500 with no body.
        Some(Err(_)) => return Ok(Ok(json!({ "status": 500, "headers": [], "body": "" }))),
        Some(Ok(r)) => r,
    };
    let (parts, mut body) = response.into_parts();
    let end = end_of(&mut body);
    if end == End::Aborted {
        return Ok(Err(wasmtime::format_err!("the handler aborted its response body")));
    }
    let bytes = store.data().http.response_body.as_ref().map(contents).unwrap_or_default();
    let pairs = |h: &http::HeaderMap| -> Vec<Value> { h.iter().map(|(k, v)| json!([k.as_str(), String::from_utf8_lossy(v.as_bytes())])).collect() };
    // Text as text; other bytes as a list of bytes, so the record stays lossless.
    let body = match String::from_utf8(bytes) {
        Ok(t) => json!(t),
        Err(e) => json!(e.into_bytes()),
    };
    let mut out = json!({ "status": parts.status.as_u16(), "headers": pairs(&parts.headers), "body": body });
    if let End::Trailers(t) = &end {
        out["trailers"] = json!(pairs(t));
    }
    Ok(Ok(out))
}

#[cfg(test)]
mod tests {
    use super::deliver_uri;

    #[test]
    fn uris_arrive_as_an_attacker_sends_them() {
        let d = |s: &str| deliver_uri(s).map(|u| u.to_string());
        assert_eq!(d("/?sku=a'b").as_deref(), Some("/?sku=a'b"));
        assert_eq!(d("https://app.example/x?q=../(1)").as_deref(), Some("https://app.example/x?q=../(1)"));
        assert_eq!(d("adminone").as_deref(), Some("/adminone"));
        assert_eq!(d("/a b<c>\"d").as_deref(), Some("/a%20b%3Cc%3E\"d"));
        assert_eq!(d("/?x=a\r\nb").as_deref(), Some("/?x=a%0D%0Ab"));
        assert_eq!(d("/ü").as_deref(), Some("/ü"));
    }
}
