//! Destinations nobody asked for: URLs in the output or in host arguments
//! that point off the host, into the internal network or at another app,
//! and where they came from. A run only receives the request and host
//! results, so a target found in neither was written into the app.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::labels::Label;
use crate::manifest::{Effect, Manifest};
use crate::record::{OutcomeKind, RunRecord};
use crate::urls::{self, classify, normalize, url_like};

/// Distinct destinations from the app's own code before a run counts as probing.
pub const PROBE_MIN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    OffHost,
    Internal,
    OtherApp,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::OffHost => "off_host",
            Class::Internal => "internal",
            Class::OtherApp => "other_app",
        }
    }
    fn says(self) -> &'static str {
        match self {
            Class::OffHost => "another host",
            Class::Internal => "the internal network",
            Class::OtherApp => "another app's route",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Request(String),
    Host(String),
    Binary,
}

/// One destination: what it is, the part that decides where it goes, and
/// the part used for probing (host and port).
#[derive(Debug, Clone)]
pub struct Dest {
    pub url: String,
    pub class: Class,
    pub target: String,
    pub endpoint: String,
    /// The host as written, before a parser turned `1024` into `0.0.4.0`.
    pub written: String,
}

/// Any URL with a host of its own, granted or not.
pub fn absolute(url: &str) -> Option<Dest> {
    let u = normalize(url);
    let (kind, host, _) = classify(&u);
    if !matches!(kind.as_str(), "external" | "protocol_relative" | "backslash" | "ip") {
        return None;
    }
    let host = host?.to_ascii_lowercase();
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let class = if is_internal(&bare) { Class::Internal } else { Class::OffHost };
    let abs = if kind == "external" || kind == "ip" { u.clone() } else { format!("https:{}", u.replace('\\', "/")) };
    let port = url::Url::parse(&abs).ok().and_then(|p| p.port_or_known_default()).map(|p| format!(":{p}")).unwrap_or_default();
    let written = written_host(&u);
    Some(Dest { url: u, class, endpoint: format!("{bare}{port}"), target: bare, written })
}

/// Where a URL goes, if it leaves the app.
pub fn destination(url: &str, m: &Manifest) -> Option<Dest> {
    let u = normalize(url);
    match classify(&u).0.as_str() {
        "external" | "protocol_relative" | "backslash" | "ip" => {
            let d = absolute(&u)?;
            (d.class == Class::Internal || !granted(&d.target, m.grants.hosts.as_deref().unwrap_or_default())).then_some(d)
        }
        "same_host" => {
            let base = m.app.base.as_deref()?.trim_end_matches('/');
            if !u.starts_with('/') || base.is_empty() {
                return None;
            }
            let path = u.split(['?', '#']).next().unwrap_or("");
            if path == base || path.starts_with(&format!("{base}/")) {
                return None;
            }
            let target = path.split('/').filter(|s| !s.is_empty()).take(2).fold(String::new(), |a, s| a + "/" + s);
            let target = if target.is_empty() { "/".to_string() } else { target };
            Some(Dest { url: u, class: Class::OtherApp, endpoint: target.clone(), written: target.clone(), target })
        }
        _ => None,
    }
}

/// The authority of an absolute URL as written, without user info and port.
fn written_host(u: &str) -> String {
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(u).trim_start_matches(['/', '\\']);
    let auth = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
    let host = if auth.starts_with('[') { auth.split_inclusive(']').next().unwrap_or(auth) } else { auth.split(':').next().unwrap_or(auth) };
    host.to_ascii_lowercase()
}

/// Loopback, private, link-local and unique-local addresses, and names
/// that only resolve inside a network.
pub fn is_internal(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    if h == "localhost" || [".localhost", ".internal", ".local", ".lan", ".home.arpa", ".intranet", ".corp"].iter().any(|s| h.ends_with(s)) {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified() || a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments()[0];
            a.is_loopback()
                || a.is_unspecified()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80
                || a.to_ipv4_mapped().is_some_and(|v| is_internal(&v.to_string()))
        }
        Err(_) => false,
    }
}

fn granted(host: &str, hosts: &[String]) -> bool {
    hosts.iter().any(|g| {
        let g = g.trim().trim_start_matches("*.").to_ascii_lowercase();
        g == "*" || host == g || host.ends_with(&format!(".{g}"))
    })
}

/// Strings of 4 characters or more in a value.
fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.chars().count() >= 4 => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// Where the deciding part of a destination came from. `before`: only host
/// results of calls before this one count.
pub fn origin(r: &RunRecord, d: &Dest, before: Option<u32>) -> Origin {
    let ts = origin_targets(d);
    let hit = |s: &String| origin_matches(&s.to_ascii_lowercase(), &ts);
    let mut req = Vec::new();
    r.spec.args.iter().for_each(|a| strings(a, &mut req));
    if let Some(s) = req.iter().find(|s| hit(s)) {
        return Origin::Request(s.clone());
    }
    for e in r.events.iter().filter(|e| before.is_none_or(|n| e.n < n)) {
        let mut got = Vec::new();
        if let Some(v) = &e.result {
            strings(v, &mut got);
        }
        if got.iter().any(hit) {
            return Origin::Host(format!("{}#{}", e.func, e.n));
        }
    }
    Origin::Binary
}

fn origin_targets(d: &Dest) -> Vec<String> {
    [&d.target, &d.written].iter().filter(|t| !t.is_empty()).map(|t| t.to_ascii_lowercase()).collect()
}

fn origin_matches(source: &str, targets: &[String]) -> bool {
    // The input holds the target, or at least half of it.
    targets.iter().any(|target| source.contains(target.as_str()) || target.contains(source) && source.len() * 2 >= target.len())
}

/// Reuse source matching when checking many destinations in one trace. Keep
/// the earliest matching call number, so future results never explain an
/// earlier call, even when callers supply events with nonmonotonic numbers.
pub(crate) struct OriginIndex {
    request: BTreeSet<String>,
    host: BTreeMap<String, u32>,
    cache: BTreeMap<(String, String), (bool, Option<u32>)>,
}

impl OriginIndex {
    pub(crate) fn new(r: &RunRecord) -> Self {
        let mut request = Vec::new();
        r.spec.args.iter().for_each(|value| strings(value, &mut request));
        let request = request.into_iter().map(|source| source.to_ascii_lowercase()).collect();
        let mut host = BTreeMap::<String, u32>::new();
        for event in &r.events {
            let mut sources = Vec::new();
            if let Some(value) = &event.result {
                strings(value, &mut sources);
            }
            for source in sources {
                host.entry(source.to_ascii_lowercase()).and_modify(|n| *n = (*n).min(event.n)).or_insert(event.n);
            }
        }
        Self { request, host, cache: BTreeMap::new() }
    }

    pub(crate) fn is_binary(&mut self, d: &Dest, before: Option<u32>) -> bool {
        let (request, first_host) = self.cache.entry((d.target.clone(), d.written.clone())).or_insert_with(|| {
            let targets = origin_targets(d);
            let request = self.request.iter().any(|source| origin_matches(source, &targets));
            let first_host = self.host.iter().filter(|(source, _)| origin_matches(source, &targets)).map(|(_, n)| *n).min();
            (request, first_host)
        });
        !*request && first_host.is_none_or(|n| before.is_some_and(|cutoff| n >= cutoff))
    }
}

/// Destinations in a host argument: absolute URLs anywhere in the text,
/// and the whole value when it has the shape of a URL or host.
pub fn in_arg(s: &str, whole: bool) -> Vec<String> {
    let mut out: Vec<String> = urls::text_urls(s);
    let t = s.trim();
    if (whole || url_like(t)) && !t.contains(char::is_whitespace) && !out.iter().any(|u| u == t) {
        let lower = t.to_ascii_lowercase();
        let has_scheme = lower.find("://").is_some_and(|i| i > 0 && lower[..i].bytes().all(|b| b.is_ascii_alphanumeric()));
        if has_scheme || t.starts_with("//") || t.starts_with("\\\\") {
            out.push(t.to_string());
        } else if !t.starts_with(['/', '.', '?', '#']) {
            out.push(format!("http://{t}"));
        }
    }
    out
}

/// `unexpected_destination` and `probing` for one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let mut out = Vec::new();
    let mut from_binary: BTreeSet<String> = BTreeSet::new();
    // Without grants nothing says which hosts the app may call: one
    // written into it is a hint, and only internal ones are probing.
    let listed = m.grants.lists_hosts();
    let mut own = |d: &Dest, o: &Origin| {
        if *o == Origin::Binary && (listed || d.class != Class::OffHost) {
            from_binary.insert(d.endpoint.clone());
        }
    };
    let mut seen = BTreeSet::new();
    let mut report = |out: &mut Vec<Finding>, d: &Dest, o: &Origin, place: &str, how: &str, strong: bool| {
        let sev = match (o, d.class) {
            (Origin::Request(_), _) => return,
            (Origin::Host(_), Class::OffHost) => return,
            (Origin::Host(_), _) => Severity::Warn,
            (Origin::Binary, Class::Internal) => Severity::Fail,
            (Origin::Binary, Class::OffHost) if !listed => Severity::Info,
            (Origin::Binary, _) if strong => Severity::Fail,
            (Origin::Binary, _) => Severity::Warn,
        };
        if !seen.insert((d.class, d.target.clone(), place.to_string())) {
            return;
        }
        let (from, src) = match o {
            Origin::Host(c) => (format!("host data ({c})"), json!(c)),
            _ => ("the app's own code".to_string(), json!("binary")),
        };
        let short: String = d.url.chars().take(100).collect();
        let title = if sev == Severity::Info {
            format!(
                "{ex} {how} aimed at {} ({short}), written into the app: add `[grants] hosts = [\"{}\"]` if the platform allows it, so that other hosts are reported",
                d.target, d.target
            )
        } else if d.class == Class::OffHost {
            format!("{ex} {how} aimed at another host ({short}), which `[grants] hosts` doesn't list; the target comes from {from}")
        } else {
            format!("{ex} {how} aimed at {} ({short}); the target comes from {from}", d.class.says())
        };
        out.push(Finding::new(
            "unexpected_destination",
            &format!("{ex}\0{}\0{}\0{place}", d.class.name(), d.target),
            sev,
            title,
            json!({"url": d.url, "class": d.class.name(), "target": d.target, "where": place, "how": how, "from": src}),
            run,
        ));
    };

    if r.outcome.kind == OutcomeKind::Ok {
        for u in urls::extract_output(r, m) {
            if !matches!(u.trigger.as_str(), "load" | "form" | "auto" | "unknown" | "redirect" | "refresh") {
                continue;
            }
            let Some(d) = destination(&u.url, m) else { continue };
            let o = origin(r, &d, None);
            own(&d, &o);
            let how = match u.trigger.as_str() {
                "load" => "a load",
                "form" => "a form",
                "redirect" | "refresh" => "a redirect",
                "auto" => "a request that fires by itself",
                _ if u.source == "script" => "a URL in a script",
                _ => "a URL in an attribute",
            };
            report(&mut out, &d, &o, &format!("output {}", u.source), &format!("outputs {how} ({})", u.source), true);
        }
    }
    for e in &r.events {
        let fetch = m.effect_of(&e.func) == Some(Effect::External);
        for (p, v) in &e.args {
            let labelled = m.param_label(&e.func, p) == Some(Label::Url);
            let mut ss = Vec::new();
            strings(v, &mut ss);
            for s in ss {
                for u in in_arg(&s, labelled) {
                    let Some(d) = destination(&u, m) else { continue };
                    if d.class == Class::OtherApp && !labelled {
                        continue;
                    }
                    let o = origin(r, &d, Some(e.n));
                    own(&d, &o);
                    report(&mut out, &d, &o, &e.func, &format!("calls {} with {p}", e.func), labelled || fetch);
                }
            }
        }
    }
    if from_binary.len() >= PROBE_MIN {
        let list: Vec<&String> = from_binary.iter().take(12).collect();
        out.push(Finding::new(
            "probing",
            ex,
            Severity::Fail,
            format!(
                "{ex} names {} destinations of its own in one run ({})",
                from_binary.len(),
                list.iter().take(4).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
            json!({"destinations": from_binary.len(), "examples": list}),
            run,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_origins_preserve_source_and_call_boundaries() {
        use crate::envelope::{Trace, TraceCall};

        for request in [json!(null), json!({"nested":["API.Example", "1024"]}), json!(["abc", "éé", "éééé"])] {
            let mut run = Trace {
                args: vec![request],
                events: [json!("API.Example"), json!({"nested":["other.example", "1024"]}), json!("API.Example"), json!(["abc", "éé", "éééé"])]
                    .into_iter()
                    .map(|result| TraceCall { result: Some(result), ..Default::default() })
                    .collect(),
                ..Default::default()
            }
            .to_record();
            // Imported traces need not put call numbers in ascending order.
            for (event, n) in run.events.iter_mut().zip([9, 2, 2, 1]) {
                event.n = n;
            }
            let mut index = OriginIndex::new(&run);
            for target in ["api.example", "other.example", "unseen.example", "abc", "éé", "éééé", "0.0.4.0"] {
                let written = if target == "0.0.4.0" { "1024" } else { target };
                let d = Dest { url: String::new(), class: Class::OffHost, target: target.into(), endpoint: target.into(), written: written.into() };
                for before in [None, Some(0), Some(1), Some(2), Some(3), Some(9), Some(10), Some(u32::MAX)] {
                    assert_eq!(
                        index.is_binary(&d, before),
                        origin(&run, &d, before) == Origin::Binary,
                        "target={target}, before={before:?}, request={:?}",
                        run.spec.args
                    );
                }
            }
        }
    }

    fn manifest(extra: &str) -> Manifest {
        toml::from_str(&format!("[app]\nwasm = \"x.wasm\"\nbase = \"/apps/me\"\n{extra}")).unwrap()
    }

    #[test]
    fn classifies_destinations() {
        let m = manifest("[grants]\nhosts = [\"cdn.example.org\"]\n");
        let c = |u: &str| destination(u, &m).map(|d| (d.class, d.target));
        assert_eq!(c("http://169.254.169.254/latest/meta-data/"), Some((Class::Internal, "169.254.169.254".into())));
        assert_eq!(c("http://2852039166/"), Some((Class::Internal, "169.254.169.254".into())));
        assert_eq!(c("http://[::1]:8080/"), Some((Class::Internal, "::1".into())));
        assert_eq!(c("https://db.internal/x").unwrap().0, Class::Internal);
        assert_eq!(c("https://t.example.net/p.gif"), Some((Class::OffHost, "t.example.net".into())));
        assert_eq!(c("//evil.example/x").unwrap().0, Class::OffHost);
        assert_eq!(c("https://cdn.example.org/a.js"), None);
        assert_eq!(c("https://img.cdn.example.org/a.png"), None);
        assert_eq!(c("/apps/me/items"), None);
        assert_eq!(c("/apps/me"), None);
        assert_eq!(c("items?x=1"), None);
        assert_eq!(c("/apps/other/admin/x"), Some((Class::OtherApp, "/apps/other".into())));
        assert_eq!(c("/apps/meme"), Some((Class::OtherApp, "/apps/meme".into())));
        assert_eq!(c("mailto:a@b.c"), None);
        assert!(destination("/x", &manifest("")).is_some());
        let mut nobase = manifest("");
        nobase.app.base = None;
        assert!(destination("/x", &nobase).is_none());
        assert_eq!(destination("http://10.0.0.1:6379", &m).unwrap().endpoint, "10.0.0.1:6379");
        assert_eq!(destination("http://1024", &m).unwrap().written, "1024");
        assert_eq!(destination("//u:p@Evil.example:81/x", &m).unwrap().written, "evil.example");
    }

    #[test]
    fn hosts_written_into_the_app() {
        let found = |grants: &str, urls: &[&str]| {
            let m = manifest(&format!("{grants}[functions.\"a/http#fetch\"]\nparams = {{ url = \"url\" }}\n"));
            let events = urls
                .iter()
                .map(|u| crate::envelope::TraceCall { func: "a/http#fetch".into(), args: json!({"url": u}).as_object().unwrap().clone(), ..Default::default() })
                .collect();
            let t = crate::envelope::Trace { export: "x#handle".into(), events, ..Default::default() };
            check(&t.to_record(), &m).into_iter().map(|f| (f.kind, f.severity)).collect::<Vec<_>>()
        };
        let api = ["https://api.example/quote"];
        // No host list: a hint. A list without the host: a fail.
        assert_eq!(found("", &api), [("unexpected_destination".to_string(), Severity::Info)]);
        assert_eq!(found("[grants]\nhosts = [\"other.example\"]\n", &api), [("unexpected_destination".to_string(), Severity::Fail)]);
        assert!(found("[grants]\nhosts = [\"api.example\"]\n", &api).is_empty());
        assert_eq!(found("", &["http://169.254.169.254/"])[0].1, Severity::Fail);
        // Four APIs are no probing without a host list; four internal hosts are.
        let four = ["https://a.example/", "https://b.example/", "https://c.example/", "https://d.example/"];
        assert!(!found("", &four).iter().any(|(k, _)| k == "probing"));
        assert!(found("[grants]\nhosts = []\n", &four).iter().any(|(k, _)| k == "probing"));
        // Other grants and no hosts: none granted.
        assert_eq!(found("[grants]\nwasi = [\"wasi:io\"]\n", &api)[0].1, Severity::Fail);
        let internal = ["http://10.0.0.1/", "http://10.0.0.2/", "http://10.0.0.3/", "http://10.0.0.4/"];
        assert!(found("", &internal).iter().any(|(k, _)| k == "probing"));
    }

    #[test]
    fn reads_arguments() {
        assert_eq!(in_arg("see https://x.example/a.", false), ["https://x.example/a"]);
        assert_eq!(in_arg("10.0.0.5:6379", false), ["http://10.0.0.5:6379"]);
        assert_eq!(in_arg("api.example.com", true), ["http://api.example.com"]);
        assert!(in_arg("hello world", false).is_empty());
        assert!(in_arg("/local/path", false).is_empty());
    }
}
