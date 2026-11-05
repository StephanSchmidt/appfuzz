//! Payloads nobody explains: values that leave in disguise, and blobs the
//! app writes from its own code.
//!
//! `encoded_flow`: a request or host value shows up base64-, hex- or
//! URL-encoded, or reversed, where its plain form would be a finding (or,
//! for unlabelled values, in a write or external call).
//! `constant_payload`: a long, random-looking string from the binary goes
//! to a write or external call. Neither the request nor the host gave it.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::labels::{Label, values_at};
use crate::manifest::{Effect, Manifest};
use crate::record::RunRecord;

/// Shortest value whose encodings are looked for.
pub const ENCODED_MIN: usize = 8;
/// Characters of a value whose encodings are looked for.
pub const ENCODED_PREFIX: usize = 48;
/// Shortest string that counts as a payload.
pub const PAYLOAD_MIN: usize = 24;
/// Bits per character above which a string looks random.
pub const ENTROPY_MIN: f64 = 3.5;

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_-]+").unwrap());

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(b: &[u8]) -> String {
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The base64 text of `v` wherever it starts in a longer blob: for each of
/// the three alignments, the characters that depend on `v` alone.
fn base64_needles(v: &[u8]) -> Vec<String> {
    (0..3)
        .filter_map(|k| {
            let mut b = vec![0u8; k];
            b.extend_from_slice(v);
            let enc = base64(&b);
            let start = if k == 0 { 0 } else { 4 };
            let end = 4 * (b.len() / 3);
            (end > start + 7).then(|| enc[start..end.min(enc.len())].to_string())
        })
        .collect()
}

fn url_encode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Encoded forms of a value: (encoding, text to look for).
pub fn encodings(v: &str, labelled: bool) -> Vec<(&'static str, String)> {
    // The encoding of a prefix is inside the encoding of the whole value.
    let v = &v[..v.char_indices().nth(ENCODED_PREFIX).map(|(i, _)| i).unwrap_or(v.len())];
    let mut out = Vec::new();
    for n in base64_needles(v.as_bytes()) {
        let url = n.replace('+', "-").replace('/', "_");
        out.push(("base64", n));
        out.push(("base64url", url));
    }
    let hex: String = v.bytes().map(|b| format!("{b:02x}")).collect();
    out.push(("hex", hex.to_ascii_uppercase()));
    out.push(("hex", hex));
    out.push(("reversed", v.chars().rev().collect()));
    if labelled {
        // Ordinary for search terms in a URL; a disguise only for secrets.
        out.push(("url-encoded", url_encode(v)));
        out.push(("url-encoded", url_encode(v).to_ascii_lowercase()));
        out.push(("percent-escaped", v.bytes().map(|b| format!("%{b:02x}")).collect()));
    }
    let mut seen = BTreeSet::new();
    out.retain(|(_, n)| n != v && n.len() >= ENCODED_MIN && seen.insert(n.clone()));
    out
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// A string that looks like random or encoded data, not words or a template.
pub fn looks_random(t: &str) -> bool {
    let classes = [t.bytes().any(|b| b.is_ascii_uppercase()), t.bytes().any(|b| b.is_ascii_lowercase()), t.bytes().any(|b| b.is_ascii_digit())];
    let hex = t.len() >= 32 && t.bytes().all(|b| b.is_ascii_hexdigit());
    t.len() >= PAYLOAD_MIN && entropy(t) >= ENTROPY_MIN && (hex || classes.iter().all(|x| *x))
}

fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

struct Source {
    value: String,
    label: Option<Label>,
    from: String,
}

/// Labelled values always; other request and host values only when
/// `unlabelled` (a write or external call could carry them).
fn sources(r: &RunRecord, m: &Manifest, unlabelled: bool) -> Vec<Source> {
    let mut out: Vec<Source> = Vec::new();
    let mut seen = BTreeSet::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.call_result_labels(&e.func, &e.args) {
            if matches!(l, Label::Pii | Label::Secret) {
                for s in values_at(v, &p) {
                    if s.chars().count() >= ENCODED_MIN && seen.insert(s.clone()) {
                        let from = if p.is_empty() { e.func.clone() } else { format!("{} {p}", e.func) };
                        out.push(Source { value: s, label: Some(l), from });
                    }
                }
            }
        }
    }
    if !unlabelled {
        return out;
    }
    let mut add = |v: &Value, from: &str| {
        let mut ss = Vec::new();
        strings(v, &mut ss);
        for s in ss {
            if s.chars().count() >= ENCODED_MIN && seen.insert(s.clone()) {
                out.push(Source { value: s, label: None, from: from.to_string() });
            }
        }
    };
    for a in &r.spec.args {
        add(a, "the request");
    }
    for e in &r.events {
        if let Some(v) = &e.result {
            add(v, &e.func);
        }
    }
    out
}

/// `encoded_flow` and `constant_payload` for one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    // Most runs have neither labelled values nor writes: nothing to look for.
    let effects = r.events.iter().any(|e| matches!(m.effect_of(&e.func), Some(Effect::Write | Effect::External)));
    let srcs = sources(r, m, effects);
    if srcs.is_empty() {
        return Vec::new();
    }
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let mut out = Vec::new();
    let resp = crate::output::response(r, m);
    let no_pii = m.entry.as_ref().is_some_and(|e| e.no_pii && crate::harness::fn_key_eq(&e.export, ex));
    // Places: (name, text, label of the parameter, a write or external call).
    let mut places: Vec<(String, String, Option<Label>, bool)> = vec![
        ("the log (stdout)".into(), r.stdout.clone(), None, false),
        ("the log (stderr)".into(), r.stderr.clone(), None, false),
        ("the response body".into(), resp.body.clone().unwrap_or_default(), None, false),
    ];
    if let Some(text) = &r.guest_error {
        places.push(("the guest error".into(), text.clone(), None, false));
    }
    for (h, v) in &resp.headers {
        places.push((format!("the response header {h}"), v.clone(), None, false));
    }
    for e in &r.events {
        let effect = matches!(m.effect_of(&e.func), Some(Effect::Write | Effect::External));
        for (p, a) in &e.args {
            let mut ss = Vec::new();
            strings(a, &mut ss);
            places.push((format!("the parameter {p} of {}", e.func), ss.join("\n"), m.param_label(&e.func, p), effect));
        }
    }

    for s in &srcs {
        let encs = encodings(&s.value, s.label.is_some());
        for (place, text, plabel, effect) in &places {
            if text.len() < ENCODED_MIN || text.contains(&s.value) || (s.label.is_some() && *plabel == s.label) {
                continue;
            }
            let sev = match s.label {
                Some(Label::Secret) => Severity::Fail,
                Some(_) if place == "the response body" && !no_pii => Severity::Warn,
                Some(_) => Severity::Fail,
                None if *effect => Severity::Warn,
                None => continue,
            };
            let Some((enc, needle)) = encs.iter().find(|(_, n)| text.contains(n.as_str())) else { continue };
            let what = match s.label {
                Some(Label::Secret) => "the secret",
                Some(_) => "the personal data",
                None => "a value",
            };
            out.push(Finding::new(
                "encoded_flow",
                &format!("{ex}\0{}\0{place}", s.from),
                sev,
                format!("{what} from {} ends up {enc} in {place}", s.from),
                json!({"from": s.from, "label": s.label.map(|l| l.name()), "value": s.value, "encoding": enc, "encoded": needle, "place": place}),
                run,
            ));
        }
    }

    // Blobs from the binary in writes and external calls.
    let mut seen = BTreeSet::new();
    for e in &r.events {
        if !matches!(m.effect_of(&e.func), Some(Effect::Write | Effect::External)) {
            continue;
        }
        for (p, a) in &e.args {
            let mut ss = Vec::new();
            strings(a, &mut ss);
            for s in ss {
                for t in TOKEN.find_iter(&s).map(|t| t.as_str()) {
                    if !looks_random(t) || !m.binary.contains(t) || srcs.iter().any(|x| x.value.contains(t) || t.contains(&x.value)) {
                        continue;
                    }
                    if !seen.insert((e.func.clone(), t.to_string())) {
                        continue;
                    }
                    out.push(Finding::new(
                        "constant_payload",
                        &format!("{ex}\0{}\0{t}", e.func),
                        Severity::Warn,
                        format!("{} gets {p} with a {}-character blob from the app's own code ({}…)", e.func, t.len(), t.chars().take(16).collect::<String>()),
                        json!({"func": e.func, "param": p, "n": e.n, "blob": {"untrusted": t}, "length": t.len(), "entropy": (entropy(t) * 100.0).round() / 100.0}),
                        run,
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes() {
        assert_eq!(base64(b"hello world"), "aGVsbG8gd29ybGQ");
        let v = "sk_live_0123456789";
        let encs = encodings(v, true);
        // Found at any offset inside a longer base64 blob.
        for prefix in ["", "x", "xy", "xyz"] {
            let blob = base64(format!("{prefix}key={v};").as_bytes());
            assert!(encs.iter().any(|(e, n)| *e == "base64" && blob.contains(n.as_str())), "{prefix}: {blob}");
        }
        let hex: String = v.bytes().map(|b| format!("{b:02x}")).collect();
        assert!(encs.iter().any(|(_, n)| *n == hex));
        assert!(encs.iter().any(|(e, n)| *e == "reversed" && n == "9876543210_evil_ks"));
        assert!(!encodings("abcdefgh123", false).iter().any(|(e, _)| e.starts_with("url")));
        assert!(encodings("a@b.example", true).iter().any(|(e, n)| *e == "url-encoded" && n == "a%40b.example"));
    }

    #[test]
    fn random_or_not() {
        assert!(looks_random("ZXhmaWw6IGFnZW50LTQyIC0+IGFnZW50LTcgaGFuZG9mZg"));
        assert!(looks_random("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        assert!(!looks_random("Thank-you-for-your-order-we-will-ship-soon"));
        assert!(!looks_random("bench_web_handler_handle_v2"));
        assert!(!looks_random("short1A"));
    }
}
