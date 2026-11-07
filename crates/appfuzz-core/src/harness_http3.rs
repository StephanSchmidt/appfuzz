//! wasi:http 0.3 in a run (Spin 4's default `http-rust` template).
//!
//! A 0.3 handler is an `async func`. The guest runs as tasks that wasmtime
//! schedules, and it keeps writing the response body after `handle` returns.
//! A run drives that event loop on its own thread without an async runtime.
//! Everything a task can wait for belongs to the run: a guest stream, or a
//! simulated host call that answers at once. So a poll that wakes nothing
//! means nothing ever will. That is a deadlock, reported as a hang, and the
//! same input gives the same report every time. Host answers are on their
//! way in virtual time ([`InFlight`]): while one is, the run waits for it.
//!
//! wasmtime-wasi-http provides the resources (requests, responses, fields,
//! bodies). appfuzz replaces `client.send`. It reads the request body to its
//! end (the guest writes it from a task of its own) and asks the same
//! interceptor as 0.2's outgoing handler, under the same key.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use serde_json::{Value, json};
use wasmtime::component::{Accessor, Func, Linker, Resource, Val};
use wasmtime::{AsContextMut, Store};
use wasmtime_wasi_http::WasiHttpView;
use wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p3::{Request, Response};

use super::{Host, intercept_values};
use crate::natural::Natural;
use crate::value::val_to_json;
use crate::wasi::VirtualClock;
use crate::wasi_http::CLIENT_KEY;

/// The wasi:http version wasmtime-wasi-http 50 provides.
const VERSION: &str = "0.3.0";

type Body = UnsyncBoxBody<Bytes, wasmtime_wasi_http::Error>;

pub(super) fn link(linker: &mut Linker<Host>) -> Result<()> {
    wasmtime_wasi_http::p3::add_to_linker(linker)?;
    let mut client = linker.instance(&format!("wasi:http/client@{VERSION}"))?;
    client
        .func_wrap_concurrent("send", |accessor: &Accessor<Host>, (req,): (Resource<Request>,)| Box::pin(async move { Ok((send(accessor, req).await?,)) }))?;
    Ok(())
}

/// How a body ended.
#[derive(Default, PartialEq)]
enum End {
    /// The guest still holds it: the run stopped first.
    #[default]
    Open,
    Finished,
    /// The guest reported an error instead of finishing it.
    Aborted,
}

/// Reads a body the guest writes, up to [`super::http::MAX_BODY`].
async fn read(body: &mut Body, into: &Mutex<Captured>) -> wasmtime::Result<()> {
    loop {
        let frame = body.frame().await;
        let mut c = into.lock().unwrap_or_else(|e| e.into_inner());
        match frame {
            None => {
                c.end = End::Finished;
                return Ok(());
            }
            Some(Err(_)) => {
                c.end = End::Aborted;
                return Ok(());
            }
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if c.body.len() + data.len() > super::http::MAX_BODY {
                        return Err(wasmtime::format_err!("an HTTP body over {} MiB", super::http::MAX_BODY >> 20));
                    }
                    c.body.extend_from_slice(&data);
                }
                Err(frame) => {
                    if let Ok(t) = frame.into_trailers() {
                        c.trailers = Some(t);
                    }
                }
            },
        }
    }
}

/// What the guest sent so far: the response head, its body and its end.
#[derive(Default)]
struct Captured {
    head: Option<(http::StatusCode, http::HeaderMap)>,
    /// The handler returned an error code instead of a response.
    error: bool,
    body: Vec<u8>,
    trailers: Option<http::HeaderMap>,
    end: End,
}

/// `client.send`: the whole request as one simulated host call.
async fn send(accessor: &Accessor<Host>, req: Resource<Request>) -> wasmtime::Result<Result<Resource<Response>, ErrorCode>> {
    let converted = accessor.with(|mut access| -> wasmtime::Result<_> {
        let req = access.as_context_mut().data_mut().table.delete(req)?;
        Ok(req.into_http(&mut access, async { Ok(()) }))
    })?;
    let (req, options) = match converted {
        Ok(r) => r,
        Err(e) => return Ok(Err(e.downcast()?)),
    };
    let (parts, mut body) = req.into_parts();
    let sent = Mutex::new(Captured::default());
    read(&mut body, &sent).await?;
    let sent = sent.into_inner().unwrap_or_else(|e| e.into_inner());
    if sent.end != End::Finished {
        // The guest gave up on the body: the request never completes.
        return Ok(Err(ErrorCode::HttpProtocolError));
    }
    let deadline_ns = options.and_then(|o| o.first_byte_timeout.map(|f| super::http::response_deadline_ns(f, o.connect_timeout.unwrap_or_default())));
    let headers: Vec<Value> = parts.headers.iter().map(|(k, v)| json!([k.as_str(), String::from_utf8_lossy(v.as_bytes())])).collect();
    let answer = accessor.with(|mut access| -> wasmtime::Result<(Value, (InFlight, VirtualClock, Natural))> {
        let mut store = access.as_context_mut();
        let body = match String::from_utf8(sent.body) {
            Ok(text) => json!(text),
            Err(error) => {
                let bytes = error.into_bytes();
                // JSON values are wider than bytes. Stop with explicitly
                // incomplete evidence before materializing an oversized array.
                let footprint = bytes.len().saturating_mul(std::mem::size_of::<Value>());
                if footprint > super::TRACE_BYTE_CAPACITY.saturating_sub(store.data().trace_bytes) {
                    return Err(super::TraceCaptureLimit::Bytes.into());
                }
                json!(bytes)
            }
        };
        let ty = store.data().platform.funcs.get(CLIENT_KEY).map(|f| f.ty.clone()).ok_or_else(|| wasmtime::format_err!("{CLIENT_KEY} is not linked"))?;
        let args = [json!(parts.method.as_str()), json!(parts.uri.to_string()), Value::Array(headers), body];
        let params = ty.params().zip(args).map(|((name, _), value)| (name.to_string(), value)).collect();
        let mut results = vec![Val::Bool(false)];
        store.data_mut().call_deadline_ns = deadline_ns;
        let sent = sent_now(&mut store);
        let called = intercept_values(store.as_context_mut(), CLIENT_KEY, params, &mut results);
        store.data_mut().call_started_ns = None;
        called.map_err(wasmtime::Error::from_anyhow)?;
        Ok((val_to_json(&results[0]), ready_at(&store, sent)))
    })?;
    let (answer, (in_flight, clock, at)) = answer;
    in_flight.until(&clock, at).await;
    let response = match super::http::answer_of(&answer) {
        Ok(Ok(r)) => r,
        Ok(Err(text)) => return Ok(Err(error_code(&text))),
        Err(e) => {
            let msg = format!("{CLIENT_KEY}: {e:#}");
            accessor.with(|mut access| access.as_context_mut().data_mut().plan_error = Some(msg.clone()));
            return Err(wasmtime::format_err!(msg));
        }
    };
    let response = response.map(|b| b.map_err(|e: Infallible| -> wasmtime_wasi_http::Error { match e {} }));
    accessor.with(|mut access| {
        let mut store = access.as_context_mut();
        let view = store.data_mut().http();
        let (res, _) = Response::from_http(view.hooks, response);
        Ok(Ok(view.table.push(res)?))
    })
}

/// The virtual time a call is made at, with the guest's time up to date.
/// The call then counts its latency from there instead of adding it.
pub(super) fn sent_now(store: &mut wasmtime::StoreContextMut<'_, Host>) -> Natural {
    Host::sync_guest_time(&*store);
    let now = store.data().clock.with(|c| c.elapsed_ns());
    store.data_mut().call_started_ns = Some(now.clone());
    now
}

/// When the answer of the call just made at `sent` is ready.
pub(super) fn ready_at(store: &wasmtime::StoreContextMut<'_, Host>, sent: Natural) -> (InFlight, VirtualClock, Natural) {
    let data = store.data();
    let latency = data.events.last().map_or_else(Natural::default, |e| e.latency_ns.clone());
    (data.in_flight.clone(), data.clock.clone(), sent + latency)
}

/// A host error text as the guest's error code: `connection-refused`,
/// `connection-timeout`, `dns-timeout`, … or an internal error.
fn error_code(text: &str) -> ErrorCode {
    match text {
        "dns-timeout" => ErrorCode::DnsTimeout,
        "destination-not-found" => ErrorCode::DestinationNotFound,
        "destination-unavailable" => ErrorCode::DestinationUnavailable,
        "connection-refused" => ErrorCode::ConnectionRefused,
        "connection-terminated" => ErrorCode::ConnectionTerminated,
        "connection-timeout" => ErrorCode::ConnectionTimeout,
        "connection-read-timeout" => ErrorCode::ConnectionReadTimeout,
        "connection-limit-reached" => ErrorCode::ConnectionLimitReached,
        "tls-certificate-error" => ErrorCode::TlsCertificateError,
        "http-request-denied" => ErrorCode::HttpRequestDenied,
        "http-response-incomplete" => ErrorCode::HttpResponseIncomplete,
        "http-response-timeout" => ErrorCode::HttpResponseTimeout,
        other => ErrorCode::InternalError(Some(other.to_string())),
    }
}

/// The request with the scheme and authority the platform gives every
/// incoming request: the client's `Host`, else the app's host.
fn with_origin(req: http::Request<http_body_util::Full<Bytes>>) -> http::Request<http_body_util::Full<Bytes>> {
    let (mut parts, body) = req.into_parts();
    if parts.uri.authority().is_none() {
        let host = parts.headers.get(http::header::HOST).and_then(|h| h.to_str().ok()).and_then(|h| http::uri::Authority::try_from(h).ok());
        let mut uri = parts.uri.clone().into_parts();
        uri.scheme = Some(http::uri::Scheme::HTTP);
        uri.authority = Some(host.unwrap_or_else(|| http::uri::Authority::from_static("app.example")));
        if uri.path_and_query.is_none() {
            uri.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
        }
        if let Ok(uri) = http::Uri::from_parts(uri) {
            parts.uri = uri;
        }
    }
    http::Request::from_parts(parts, body)
}

/// Calls `wasi:http/handler#handle` with the request record and captures
/// the response, also one a trap cut short: its head and the body bytes
/// already sent stay output. The outer error is appfuzz's (a request the
/// platform would not deliver), the inner one the guest's.
pub(super) fn call_handler(store: &mut Store<Host>, func: Func, request: &Value) -> Result<std::result::Result<(), wasmtime::Error>> {
    let req = with_origin(super::http::incoming_request(request)?);
    let req = req.map(|b| b.map_err(|e: Infallible| -> wasmtime_wasi_http::Error { match e {} }));
    let (req, _) = Request::from_http(store.data_mut().http().hooks, req);
    let handle = func
        .typed::<(Resource<Request>,), (Result<Resource<Response>, ErrorCode>,)>(&*store)
        .map_err(anyhow::Error::from)
        .context("the wasi:http 0.3 handler's type")?;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let into = captured.clone();
    let (in_flight, clock) = (store.data().in_flight.clone(), store.data().clock.clone());
    let run = store.run_concurrent(async move |accessor| -> wasmtime::Result<()> {
        let req = accessor.with(|mut access| access.as_context_mut().data_mut().table.push(req))?;
        let (res,) = handle.call_concurrent(accessor, (req,)).await?;
        let Ok(res) = res else {
            into.lock().unwrap_or_else(|e| e.into_inner()).error = true;
            return Ok(());
        };
        let response = accessor.with(|mut access| -> wasmtime::Result<_> {
            let res = access.as_context_mut().data_mut().table.delete(res)?;
            res.into_http(&mut access, async { Ok(()) })
        })?;
        let (parts, mut body) = response.into_parts();
        into.lock().unwrap_or_else(|e| e.into_inner()).head = Some((parts.status, parts.headers));
        read(&mut body, &into).await
    });
    let called = match until_stuck(run, &in_flight, &clock) {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e),
        None => Err(wasmtime::Trap::AsyncDeadlock.into()),
    };
    let captured = std::mem::take(&mut *captured.lock().unwrap_or_else(|e| e.into_inner()));
    let pairs = |h: &http::HeaderMap| -> Vec<Value> { h.iter().map(|(k, v)| json!([k.as_str(), String::from_utf8_lossy(v.as_bytes())])).collect() };
    let finished = if captured.error {
        // The guest reports an error: the client gets a 500 with no body.
        store.data_mut().http.result = Some(json!({ "status": 500, "headers": [], "body": "" }));
        Ok(())
    } else if let Some((status, headers)) = &captured.head {
        // Text as text; other bytes as a list of bytes, so the record stays lossless.
        let body = match String::from_utf8(captured.body) {
            Ok(t) => json!(t),
            Err(e) => json!(e.into_bytes()),
        };
        let mut out = json!({ "status": status.as_u16(), "headers": pairs(headers), "body": body });
        if let Some(t) = &captured.trailers {
            out["trailers"] = json!(pairs(t));
        }
        if captured.end != End::Finished {
            out["body_complete"] = json!(false);
        }
        store.data_mut().http.result = Some(out);
        match captured.end {
            End::Aborted => Err(wasmtime::format_err!("the handler aborted its response body")),
            End::Open => Err(wasmtime::format_err!("the handler stopped before finishing its response body")),
            End::Finished => Ok(()),
        }
    } else {
        Err(wasmtime::format_err!("the handler returned no response"))
    };
    Ok(called.and(finished))
}

/// Host answers on their way. An async host call (an outbound request, a
/// Spin query) is ready at the virtual time it was made plus its latency.
/// When the app can only wait, the clock moves on to the earliest answer,
/// so calls made together overlap and calls made one after another add up.
#[derive(Clone, Default)]
pub(super) struct InFlight(Arc<Mutex<Vec<(Natural, Waker)>>>);

impl InFlight {
    /// Waits until the clock reaches `at`.
    pub(super) async fn until(&self, clock: &VirtualClock, at: Natural) {
        std::future::poll_fn(|cx| {
            if clock.with(|c| c.elapsed_ns()) >= at {
                return Poll::Ready(());
            }
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push((at.clone(), cx.waker().clone()));
            Poll::Pending
        })
        .await
    }

    /// Moves the clock to the earliest answer and wakes what it reached.
    /// False when nothing is on its way.
    fn advance(&self, clock: &VirtualClock) -> bool {
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(at) = waiting.iter().map(|(t, _)| t).min().cloned() else { return false };
        clock.with(|c| {
            let now = c.elapsed_ns();
            if at > now {
                c.host_ns += at.clone() - now;
            }
        });
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut *waiting).into_iter().partition(|(t, _)| *t <= at);
        *waiting = rest;
        drop(waiting);
        due.into_iter().for_each(|(_, w)| w.wake());
        true
    }
}

/// Notes that something woke the run.
struct Woken(AtomicBool);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Polls `fut` on this thread until it ends. When a poll leaves nothing
/// awake, the clock moves to the next host answer in flight; with none,
/// it is `None`: a run has no outside I/O, so nothing would ever wake it.
pub(super) fn until_stuck<F: Future>(fut: F, in_flight: &InFlight, clock: &VirtualClock) -> Option<F::Output> {
    let woken = Arc::new(Woken(AtomicBool::new(false)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        woken.0.store(false, Ordering::SeqCst);
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        if !woken.0.load(Ordering::SeqCst) && !in_flight.advance(clock) {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InFlight, VirtualClock};
    use crate::natural::Natural;
    use std::task::Poll;

    fn until_stuck<F: Future>(fut: F) -> Option<F::Output> {
        super::until_stuck(fut, &InFlight::default(), &VirtualClock::new(0))
    }

    #[test]
    fn a_future_that_waits_for_nothing_is_stuck() {
        assert_eq!(until_stuck(std::future::pending::<()>()), None);
        assert_eq!(until_stuck(async { 7 }), Some(7));
    }

    #[test]
    fn answers_sent_together_overlap() {
        let (in_flight, clock) = (InFlight::default(), VirtualClock::new(0));
        let ms = |n: u64| Natural::from(n * 1_000_000);
        // Two 60 ms answers awaited together, then one awaited alone.
        let run = async {
            let mut a = std::pin::pin!(in_flight.until(&clock, ms(60)));
            let mut b = std::pin::pin!(in_flight.until(&clock, ms(60)));
            let (mut a_done, mut b_done) = (false, false);
            std::future::poll_fn(|cx| {
                a_done = a_done || a.as_mut().poll(cx).is_ready();
                b_done = b_done || b.as_mut().poll(cx).is_ready();
                if a_done && b_done { Poll::Ready(()) } else { Poll::Pending }
            })
            .await;
            let now = clock.with(|c| c.elapsed_ns());
            in_flight.until(&clock, now + ms(60)).await;
        };
        assert_eq!(super::until_stuck(run, &in_flight, &clock), Some(()));
        assert_eq!(clock.with(|c| c.elapsed_ns()), ms(120));
    }

    #[test]
    fn a_future_that_wakes_itself_runs_on() {
        let mut polls = 0;
        let fut = std::future::poll_fn(|cx| {
            polls += 1;
            if polls < 3 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(polls)
            }
        });
        assert_eq!(until_stuck(fut), Some(3));
    }
}
