//! Bench app `http-fanout`: a well-behaved wasi:http handler that asks four
//! regional price services at once, waits for all of them together, and
//! shows the cheapest price, escaped.
//!
//! Each upstream takes 60 ms and the latency limit is 200 ms: sent one
//! after another the page would take 240 ms, sent together it takes 60.
//! Each request has a 100 ms first-byte timeout, so a slow region costs
//! its price, not the page.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::outgoing_handler;
use wasi::http::types::{
    Fields, FutureIncomingResponse, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse, RequestOptions, ResponseOutparam, Scheme,
};

struct A;
export!(A);

const REGIONS: [&str; 4] = ["eu", "us", "ap", "sa"];

impl Guest for A {
    fn handle(_req: IncomingRequest, out: ResponseOutparam) {
        // Send all four first, then wait for all of them.
        let futures: Vec<Option<FutureIncomingResponse>> = REGIONS.iter().map(|r| send(&format!("/{r}/price"))).collect();
        let pollables: Vec<_> = futures.iter().flatten().map(|f| f.subscribe()).collect();
        let mut ready = vec![false; pollables.len()];
        while ready.iter().any(|r| !r) {
            let waiting: Vec<_> = pollables.iter().zip(&ready).filter(|(_, r)| !**r).map(|(p, _)| p).collect();
            let idx: Vec<usize> = pollables.iter().enumerate().zip(&ready).filter(|(_, r)| !**r).map(|((i, _), _)| i).collect();
            for done in wasi::io::poll::poll(&waiting) {
                ready[idx[done as usize]] = true;
            }
        }
        drop(pollables);
        let prices: Vec<u64> = futures.iter().flatten().filter_map(|f| read(f)).filter_map(|t| t.trim().parse().ok()).collect();
        let html = match prices.iter().min() {
            Some(p) => format!("<h1>Best price</h1><p>{p} cents from {} regions</p>", prices.len()),
            None => "<h1>Prices are unavailable</h1>".to_string(),
        };
        respond(out, 200, &html);
    }
}

fn send(path: &str) -> Option<FutureIncomingResponse> {
    let req = OutgoingRequest::new(Fields::new());
    let _ = req.set_method(&Method::Get);
    let _ = req.set_scheme(Some(&Scheme::Https));
    req.set_authority(Some("prices.example")).ok()?;
    req.set_path_with_query(Some(path)).ok()?;
    let options = RequestOptions::new();
    let _ = options.set_first_byte_timeout(Some(100_000_000));
    outgoing_handler::handle(req, Some(options)).ok()
}

fn read(future: &FutureIncomingResponse) -> Option<String> {
    let resp = match future.get() {
        Some(Ok(Ok(r))) if r.status() == 200 => r,
        _ => return None,
    };
    let body = resp.consume().ok()?;
    let stream = body.stream().ok()?;
    let mut text = Vec::new();
    while let Ok(chunk) = stream.blocking_read(4096) {
        text.extend(chunk);
    }
    drop(stream);
    Some(String::from_utf8_lossy(&text).into_owned())
}

fn respond(out: ResponseOutparam, status: u16, html: &str) {
    let headers = Fields::new();
    let _ = headers.append("content-type", b"text/html; charset=utf-8");
    let resp = OutgoingResponse::new(headers);
    let _ = resp.set_status_code(status);
    let body = resp.body().expect("one body");
    ResponseOutparam::set(out, Ok(resp));
    let stream = body.write().expect("one stream");
    for chunk in html.as_bytes().chunks(4096) {
        stream.blocking_write_and_flush(chunk).expect("write");
    }
    drop(stream);
    let _ = OutgoingBody::finish(body, None);
}
