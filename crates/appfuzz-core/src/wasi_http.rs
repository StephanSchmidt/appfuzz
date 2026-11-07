//! wasi:http 0.2 and 0.3 for components, the parts that need no running store.
//!
//! An app that exports `wasi:http/incoming-handler` (0.2) or
//! `wasi:http/handler` (0.3) is called like a Fastly app: its request is one
//! record `{method, uri, headers, body}` and its result is
//! `{status, headers, body}`. Each outbound request
//! (`wasi:http/outgoing-handler#handle`, or 0.3's `wasi:http/client#send`)
//! is one simulated host function
//! `handle(method, url, headers, body) -> result<response, string>`, so
//! plans, rules, labels, latency and cost work as for any host function.
//! The resource plumbing lives in `harness_http.rs` and `harness_http3.rs`.

use anyhow::{Context, Result};
use serde_json::json;
use wasmtime::Engine;
use wasmtime::component::Component;

use crate::manifest::{Entry, FunctionSpec, Manifest, Output, strip_version};
use crate::wit::{FuncInfo, ImportKind, Interface};

pub const HANDLER: &str = "wasi:http/incoming-handler";
pub const CLIENT: &str = "wasi:http/outgoing-handler";
/// The same in wasi:http 0.3 (Spin 4's `http-rust` template, spin-sdk 7).
/// Its outbound `send` is the same simulated host function.
pub const HANDLER3: &str = "wasi:http/handler";
pub const CLIENT3: &str = "wasi:http/client";
/// The key of the simulated outbound request.
pub const CLIENT_KEY: &str = "wasi:http/outgoing-handler#handle";

/// The types appfuzz shows for the handler and for outbound requests.
const CARRIER: &str = r#"
package appfuzz:http;

interface entry {
  record request { method: string, uri: string, headers: list<tuple<string, string>>, body: string }
  record response { status: u16, headers: list<tuple<string, string>>, body: string }
  handle: func(request: request) -> response;
}

interface client {
  record response { status: u16, headers: list<tuple<string, string>>, body: string }
  handle: func(method: string, url: string, headers: list<tuple<string, string>>, body: string) -> result<response, string>;
}

world carrier {
  import client;
  export entry;
}
"#;

/// The `wasi:http/incoming-handler#handle` export, or wasi:http 0.3's
/// `wasi:http/handler#handle`.
pub fn is_handler(f: &FuncInfo) -> bool {
    is_handler_key(&f.key)
}

/// Whether a function key names an HTTP handler, either version.
pub fn is_handler_key(key: &str) -> bool {
    let (i, f) = key.split_once('#').unwrap_or(("", key));
    matches!(strip_version(i), HANDLER | HANDLER3) && f == "handle"
}

/// The wasi:http 0.3 handler, which runs as concurrent tasks.
pub fn is_handler3(f: &FuncInfo) -> bool {
    strip_version(&f.interface) == HANDLER3 && f.name == "handle"
}

pub fn is_client(interface: &str) -> bool {
    matches!(strip_version(interface), CLIENT | CLIENT3)
}

/// Whether the component needs wasi:http 0.3 linked.
pub fn uses_http3(imports: &[Interface], exports: &[FuncInfo]) -> bool {
    imports.iter().any(|i| i.name.starts_with("wasi:http/") && i.name.split_once('@').is_some_and(|(_, v)| v.starts_with("0.3")))
        || exports.iter().any(is_handler3)
}

/// Release candidates of wasi:http 0.3 (Spin 4.0's spin-sdk 6) have
/// resource types wasmtime no longer provides: say so and how to fix it,
/// instead of a type mismatch.
pub fn check_version(imports: &[Interface], exports: &[FuncInfo]) -> Result<()> {
    let names = imports.iter().map(|i| i.name.as_str()).chain(exports.iter().map(|f| f.interface.as_str()));
    for name in names {
        if let Some((i, v)) = name.split_once('@')
            && i.starts_with("wasi:http/")
            && v.starts_with("0.3.0-rc")
        {
            anyhow::bail!(
                "{name} is a release candidate of WASI 0.3 (Spin 4.0, spin-sdk 6). appfuzz runs wasi:http 0.3.0, as Spin 4.1 and later do: rebuild with spin-sdk 7"
            );
        }
    }
    Ok(())
}

/// Whether the component needs wasi:http linked.
pub fn uses_http(imports: &[Interface], exports: &[FuncInfo]) -> bool {
    imports.iter().any(|i| i.name.starts_with("wasi:http/")) || exports.iter().any(is_handler)
}

/// Gives the handler export and the outgoing-handler import their simple
/// types. The outgoing handler becomes a platform interface: a simulated
/// host function like any other.
pub fn adapt(engine: &Engine, imports: &mut [Interface], exports: &mut [FuncInfo]) -> Result<()> {
    if !uses_http(imports, exports) {
        return Ok(());
    }
    let (entry, client) = carrier(engine)?;
    for f in exports.iter_mut().filter(|f| is_handler(f)) {
        f.ty = entry.ty.clone();
    }
    for i in imports.iter_mut().filter(|i| is_client(&i.name)) {
        i.kind = ImportKind::Platform;
        i.funcs = vec![FuncInfo { interface: i.name.clone(), name: "handle".into(), key: CLIENT_KEY.into(), ty: client.ty.clone() }];
    }
    Ok(())
}

fn carrier(engine: &Engine) -> Result<(FuncInfo, FuncInfo)> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("http-carrier.wit", CARRIER).context("wasi:http carrier WIT")?;
    let world = resolve.select_world(&[pkg], Some("carrier"))?;
    let mut module = wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false)?;
    let bytes = wit_component::ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let component = Component::new(engine, &bytes).map_err(anyhow::Error::from).context("wasi:http carrier component")?;
    let entry = crate::wit::exports(engine, &component).into_iter().find(|f| f.name == "handle").context("carrier entry")?;
    let client = crate::wit::imports(engine, &component).into_iter().flat_map(|i| i.funcs).find(|f| f.name == "handle").context("carrier client")?;
    Ok((entry, client))
}

/// What the platform promises for an HTTP handler, unless the manifest
/// says otherwise: the entry is the handler, the request is a parsed HTTP
/// request, outbound URLs are SSRF sinks, outbound headers may carry
/// secrets (an `Authorization` token to the app's API is normal; sending it
/// elsewhere is SSRF or an ungranted host) and statuses are real.
pub fn default_manifest(manifest: &mut Manifest, imports: &[Interface], exports: &[FuncInfo]) -> Result<()> {
    if let Some(handler) = exports.iter().find(|f| is_handler(f)) {
        let entry = manifest.entry.get_or_insert_with(|| Entry {
            export: handler.key.clone(),
            request: None,
            fields: Default::default(),
            output: Output::default(),
            now: None,
            result: Default::default(),
            sensitive_paths: vec![],
            csp: None,
            no_pii: false,
            values: Default::default(),
            input_values: Default::default(),
        });
        // A handler named for the other wasi:http version (spin.toml says
        // nothing about which one a build exports) is this one.
        if entry.export.is_empty() || (is_handler_key(&entry.export) && !exports.iter().any(|f| crate::harness::fn_key_eq(&entry.export, &f.key))) {
            entry.export = handler.key.clone();
        }
        if crate::harness::fn_key_eq(&entry.export, &handler.key) {
            entry.request.get_or_insert_with(|| json!({ "method": "GET", "uri": "https://app.example/", "headers": [], "body": "" }));
            let o = &mut entry.output;
            if o.status.is_none() && o.body.is_none() && o.headers.is_none() {
                o.status = Some("status".into());
                o.body = Some("body".into());
                o.headers = Some("headers".into());
            }
            // The platform parses the client's HTTP before the app runs. No
            // constraint on `uri`: any text is delivered as a valid URI
            // (resolved against https://app.example/, unsafe bytes
            // percent-encoded), so no request is impossible.
            if !entry.values.contains_key("method") {
                entry.values.insert("method".into(), serde_json::from_value(json!("format:token")).context("constraint format:token")?);
            }
        }
    }
    if imports.iter().any(|i| is_client(&i.name)) {
        let defaults: FunctionSpec = toml::from_str(
            r#"
description = "Sends an HTTP request and waits for the response."
params = { url = "url", headers = "secret" }
values = { status = "range:200..599" }
"#,
        )
        .context("default outgoing-handler spec")?;
        // A manifest section keeps what it sets (a latency, its own labels);
        // what it leaves out comes from the defaults.
        let key = manifest
            .functions
            .keys()
            .find(|k| {
                let (i, f) = k.split_once('#').unwrap_or(("", k));
                crate::manifest::fn_key(i, f) == CLIENT_KEY
            })
            .cloned()
            .unwrap_or_else(|| CLIENT_KEY.into());
        let spec = manifest.functions.entry(key).or_default();
        if spec.description.is_none() {
            spec.description = defaults.description;
        }
        if spec.params.is_empty() {
            spec.params = defaults.params;
        }
        if spec.values.is_empty() {
            spec.values = defaults.values;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasi(name: &str) -> Interface {
        Interface { name: name.into(), kind: ImportKind::Wasi, funcs: vec![] }
    }

    #[test]
    fn release_candidates_of_wasi_http_03_say_how_to_fix_them() {
        let err = check_version(&[wasi("wasi:http/types@0.3.0-rc-2026-03-15")], &[]).unwrap_err().to_string();
        assert!(err.contains("spin-sdk 7"), "{err}");
        assert!(check_version(&[wasi("wasi:http/types@0.3.0"), wasi("wasi:http/types@0.2.12")], &[]).is_ok());
        assert!(check_version(&[wasi("wasi:cli/environment@0.3.0-rc-2026-03-15")], &[]).is_ok());
    }
}
