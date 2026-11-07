//! Records per response: how many records of a host collection one request
//! sends out, in the response, the logs, or calls that send data elsewhere
//! (`external` effects, outgoing HTTP). A platform declares the most one
//! response may carry (`[limits] records_per_response`, per dataset
//! `max_per_response`); more is `mass_disclosure`.
//!
//! Generated records repeat their text, so the runs that count them mark
//! each record first: the dataset edit `tag` adds a token made from the
//! record's key to its text fields, and `probe` does the same to each item
//! of a host list it grows. The check makes the tokens again from the spec
//! and looks for them.

use std::collections::{BTreeMap, BTreeSet};

use aho_corasick::{AhoCorasick, MatchKind};
use serde::Serialize;
use serde_json::{Value, json};

use crate::dataset::{Edit, World};
use crate::detect::{Finding, Severity};
use crate::harness::App;
use crate::labels::{Label, id_text};
use crate::manifest::{Effect, Manifest};
use crate::par::{self, Runner};
use crate::record::{OutcomeKind, RunRecord, RunSpec};
use crate::scale::Knob;

/// Without a declared limit, a whole collection this big leaving in one
/// request is worth a look.
pub const NO_CAP_MIN: usize = 1000;
/// Rows the probe gives a collection without a declared limit.
const NO_CAP_ROWS: usize = 1024;
/// Request keys that often set how many records come back.
const COUNT_KEYS: &[&str] = &["limit", "count", "size", "per_page", "page_size", "pagesize", "max", "n", "top", "take", "rows"];
/// Pages besides the request the probe starts from.
const MAX_STARTS: usize = 8;
/// Runs the probe spends on request fields that may lift a limit.
const MAX_FIELD_RUNS: usize = 400;

/// The token that marks record `key` of `source` (a dataset or a function).
pub fn token(source: &str, key: &str) -> String {
    let h = blake3::hash(format!("{source}\0{key}").as_bytes()).to_hex();
    format!("r{}", &h[..10])
}

/// Marks every text in `v` with `token`: an address gets `+token` before
/// its `@` (it stays an address), other text ` token` at its end.
pub fn mark(v: &mut Value, token: &str) {
    match v {
        Value::String(s) => match s.find('@') {
            Some(at) if at > 0 && s.matches('@').count() == 1 => s.insert_str(at, &format!("+{token}")),
            _ => {
                s.push(' ');
                s.push_str(token);
            }
        },
        Value::Array(a) => a.iter_mut().for_each(|x| mark(x, token)),
        Value::Object(o) => o.values_mut().for_each(|x| mark(x, token)),
        _ => {}
    }
}

/// Text fields of `dataset` a record can be marked in: not the key, the
/// owner or a reference, no field a query or mutation filters or sorts
/// on, and none whose values the platform holds to a format, a set or a
/// length.
pub fn tag_fields(m: &Manifest, dataset: &str) -> Vec<String> {
    let Some(d) = m.datasets.get(dataset) else { return vec![] };
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for f in m.functions.values() {
        let bound = f.query.as_ref().is_some_and(|q| q.dataset == dataset);
        if let Some(q) = f.query.as_ref().filter(|_| bound) {
            used.extend(q.filter.keys().map(String::as_str));
            used.extend(q.order.iter().map(String::as_str));
        }
        if let Some(mu) = f.mutation.as_ref().filter(|mu| mu.dataset == dataset) {
            used.extend(mu.filter.keys().map(String::as_str));
        }
        if bound {
            for (path, c) in &f.values {
                if !matches!(c, crate::constraints::Constraint::Range(..) | crate::constraints::Constraint::Unique(_)) {
                    used.insert(path.rsplit(['.', ']']).next().unwrap_or(path));
                }
            }
        }
    }
    d.template
        .iter()
        .filter(|(k, v)| v.is_string() && **k != d.key && d.owner.as_ref() != Some(*k) && !d.references.contains_key(*k) && !used.contains(k.as_str()))
        .map(|(k, _)| k.clone())
        .collect()
}

/// The most records of `dataset` one response may carry.
pub fn cap(m: &Manifest, dataset: Option<&str>) -> Option<u64> {
    dataset.and_then(|d| m.datasets.get(d)).and_then(|d| d.max_per_response).or(m.limits.records_per_response)
}

/// A collection whose records a run marked.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    /// The dataset, or the function whose list the plan sets.
    pub name: String,
    pub dataset: bool,
    pub total: usize,
    pub cap: Option<u64>,
    /// Its records hold `pii` or `secret` data.
    pub sensitive: bool,
}

impl Source {
    fn what(&self) -> String {
        if self.dataset { format!("{} records", self.name) } else { format!("items {} returns", self.name) }
    }
}

/// The marked records of one run and the automaton that finds them.
pub struct Counter {
    pub sources: Vec<Source>,
    ac: AhoCorasick,
    /// Per pattern: its source and record.
    needles: Vec<(usize, usize)>,
    /// Functions whose arguments leave the platform.
    outgoing: BTreeSet<String>,
}

/// The list inside a host answer: the answer, or its `ok` or `some`.
fn items(v: &Value) -> Option<&Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 => o.get("ok").or_else(|| o.get("some")).and_then(items),
        _ => None,
    }
}

fn items_mut(v: &mut Value) -> Option<&mut Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 => {
            let key = if o.contains_key("ok") { "ok" } else { "some" };
            o.get_mut(key).and_then(items_mut)
        }
        _ => None,
    }
}

/// Datasets `spec` marks with a `tag` edit.
fn tagged(spec: &RunSpec) -> Vec<&str> {
    let mut out: Vec<&str> = spec
        .plan
        .0
        .get("_defaults")
        .map(|d| d.dataset_edits.iter().filter_map(|e| if let Edit::Tag { dataset, .. } = e { Some(dataset.as_str()) } else { None }).collect())
        .unwrap_or_default();
    out.dedup();
    out
}

/// Host lists in `spec`'s plan long enough to break a limit.
fn lists<'a>(spec: &'a RunSpec, m: &Manifest) -> Vec<(&'a str, &'a Vec<Value>)> {
    let min = m.limits.records_per_response.map_or(NO_CAP_MIN, |c| c as usize + 1).min(NO_CAP_MIN);
    spec.plan
        .0
        .iter()
        .filter(|(k, _)| *k != "_defaults")
        .filter_map(|(k, p)| Some((k.as_str(), p.response.ret.as_ref().and_then(items)?)))
        .filter(|(_, l)| l.len() >= min)
        .collect()
}

/// Whether `spec` marks records: then its runs are counted.
pub fn marks(spec: &RunSpec, m: &Manifest) -> bool {
    !tagged(spec).is_empty() || !lists(spec, m).is_empty()
}

fn sensitive(m: &Manifest, func: &str) -> bool {
    m.result_labels(func).iter().any(|(_, l)| matches!(l, Label::Pii | Label::Secret))
}

impl Counter {
    /// The records `spec` marks, in the world it starts from.
    pub fn new(spec: &RunSpec, m: &Manifest, tables: &World) -> Option<Counter> {
        let mut sources = Vec::new();
        let mut patterns: Vec<String> = Vec::new();
        let mut needles = Vec::new();
        for name in tagged(spec) {
            let (Some(d), Some(rows)) = (m.datasets.get(name), tables.get(name)) else { continue };
            let s = sources.len();
            for (i, row) in rows.iter().enumerate() {
                let key = &row[&d.key];
                patterns.push(token(name, &id_text(key)));
                needles.push((s, i));
                if key.is_string() {
                    patterns.push(id_text(key));
                    needles.push((s, i));
                }
            }
            let bound = m.functions.iter().filter(|(_, f)| f.query.as_ref().is_some_and(|q| q.dataset == name));
            let sensitive = bound.map(|(k, _)| k).any(|k| sensitive(m, k));
            sources.push(Source { name: name.to_string(), dataset: true, total: rows.len(), cap: cap(m, Some(name)), sensitive });
        }
        for (func, list) in lists(spec, m) {
            let s = sources.len();
            for i in 0..list.len() {
                patterns.push(token(func, &i.to_string()));
                needles.push((s, i));
            }
            sources.push(Source { name: func.to_string(), dataset: false, total: list.len(), cap: cap(m, None), sensitive: sensitive(m, func) });
        }
        if sources.is_empty() {
            return None;
        }
        let ac = AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::Standard).build(&patterns).ok()?;
        let outgoing = m
            .functions
            .iter()
            .filter(|(_, f)| f.effect == Some(Effect::External))
            .map(|(k, _)| k.clone())
            .chain([crate::wasi_http::CLIENT_KEY.to_string()])
            .collect();
        Some(Counter { sources, ac, needles, outgoing })
    }

    /// The counter for a stored run: its world made again from the spec.
    pub fn for_run(spec: &RunSpec, m: &Manifest) -> Option<Counter> {
        if !marks(spec, m) {
            return None;
        }
        let tables = if tagged(spec).is_empty() { World::new() } else { crate::harness::initial_state(m, &spec.plan, spec.seed).ok()?.tables };
        Counter::new(spec, m, &tables)
    }

    /// Whether a call to `func` sends its arguments out.
    pub fn watches(&self, func: &str) -> bool {
        self.outgoing.contains(func)
    }

    /// Distinct records of each source in `text`, by source name.
    pub fn count(&self, text: &str) -> BTreeMap<String, u32> {
        let bytes = text.as_bytes();
        let word = |i: usize| bytes.get(i).is_some_and(u8::is_ascii_alphanumeric);
        let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
        for mat in self.ac.find_overlapping_iter(text) {
            if (mat.start() > 0 && word(mat.start() - 1)) || word(mat.end()) {
                continue;
            }
            seen.insert(self.needles[mat.pattern().as_usize()]);
        }
        let mut out = BTreeMap::new();
        for (s, _) in seen {
            *out.entry(self.sources[s].name.clone()).or_insert(0u32) += 1;
        }
        out
    }

    /// Records in the arguments of one call, as the guest passed them.
    pub fn count_call(&self, args: &[(String, Value)]) -> BTreeMap<String, u32> {
        let mut text = String::new();
        for (_, v) in args {
            texts(v, &mut text);
        }
        self.count(&text)
    }

    /// Where the records of `r` went: per place, records per source.
    pub fn places(&self, r: &RunRecord, m: &Manifest) -> Vec<(String, BTreeMap<String, u32>)> {
        let resp = crate::output::response(r, m);
        let body = resp.body.unwrap_or_else(|| r.result.as_ref().map(Value::to_string).unwrap_or_default());
        let mut out = vec![("the response".to_string(), self.count(&body)), ("the logs".to_string(), self.count(&format!("{}\n{}", r.stdout, r.stderr)))];
        let mut calls: BTreeMap<&str, BTreeMap<String, u32>> = BTreeMap::new();
        for e in r.events.iter().filter(|e| !e.records.is_empty()) {
            let place = calls.entry(e.func.as_str()).or_default();
            for (s, n) in &e.records {
                *place.entry(s.clone()).or_default() += n;
            }
        }
        out.extend(calls.into_iter().map(|(f, c)| (format!("calls to {f}"), c)));
        out
    }
}

/// Every text in `v`; a list of bytes counts as text.
fn texts(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(a) if a.len() >= 4 && a.iter().all(|b| b.as_u64().is_some_and(|b| b < 256)) => {
            let bytes: Vec<u8> = a.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect();
            out.push_str(&String::from_utf8_lossy(&bytes));
            out.push('\n');
        }
        Value::Array(a) => a.iter().for_each(|x| texts(x, out)),
        Value::Object(o) => o.values().for_each(|x| texts(x, out)),
        _ => {}
    }
}

/// `mass_disclosure` findings of one run: more marked records in one place
/// than the platform allows per response; without a limit, a whole
/// collection of at least `NO_CAP_MIN` records (warn when it holds
/// personal data or secrets).
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    if r.outcome.kind != OutcomeKind::Ok {
        return vec![];
    }
    let Some(counter) = Counter::for_run(&r.spec, m) else { return vec![] };
    let ex = &r.spec.export;
    let mut out = Vec::new();
    for (place, counts) in counter.places(r, m) {
        for s in &counter.sources {
            let n = counts.get(&s.name).copied().unwrap_or(0) as usize;
            let (severity, title) = match s.cap {
                Some(cap) if n as u64 > cap => {
                    (Severity::Fail, format!("{ex} puts {n} of {} {} into {place}; the platform allows {cap} per response", s.total, s.what()))
                }
                None if n == s.total && n >= NO_CAP_MIN => (
                    if s.sensitive { Severity::Warn } else { Severity::Info },
                    format!("{ex} puts all {n} {} into {place}; no limit per response is declared", s.what()),
                ),
                _ => continue,
            };
            out.push(Finding::new(
                "mass_disclosure",
                &format!("{ex}\0records\0{}\0{place}", s.name),
                severity,
                title,
                json!({"source": s.name, "dataset": s.dataset, "place": place, "records": n, "total": s.total, "cap": s.cap, "sensitive": s.sensitive}),
                Some(r.id.as_str()),
            ));
        }
    }
    out
}

/// What `probe records` measured for one collection.
#[derive(Debug, Clone, Serialize)]
pub struct Bound {
    pub source: String,
    pub dataset: bool,
    pub cap: Option<u64>,
    /// The most records any run had.
    pub total: usize,
    /// The most records one run put into each place.
    pub most: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize)]
pub struct Probe {
    pub runs: usize,
    pub bounds: Vec<Bound>,
    /// Collections whose records can't be told apart (no text, no text key).
    pub not_counted: Vec<String>,
    #[serde(skip)]
    pub findings: Vec<Finding>,
}

/// Pages to start from: the request and the same-host links and forms it serves.
fn starts(app: &App, base: &RunSpec, run: Runner) -> Vec<RunSpec> {
    let mut out = vec![base.clone()];
    let first = run(base);
    if first.outcome.kind != OutcomeKind::Ok {
        return out;
    }
    let fields = app.manifest.entry.as_ref().map(|e| e.fields.clone()).unwrap_or_default();
    let inputs = first.result.as_ref().map(crate::fuzz::form_inputs).unwrap_or_default();
    let ones: Vec<String> = inputs.iter().map(|_| "1".to_string()).collect();
    for u in crate::urls::extract_output(&first, &app.manifest).into_iter().filter(|u| u.kind == "same_host") {
        if out.len() > MAX_STARTS {
            break;
        }
        let mut spec = base.clone();
        if let Some(req) = spec.args.first_mut()
            && crate::fuzz::crawl_into(req, &fields, &u.url, &u.method, &inputs, &ones)
            && !out.iter().any(|s| s.args == spec.args)
        {
            out.push(spec);
        }
    }
    out
}

/// `spec` with `n` records of `source`, each marked.
fn marked(app: &App, spec: &RunSpec, source: &str, dataset: bool, n: usize) -> Option<RunSpec> {
    let mut s = spec.clone();
    if dataset {
        let d = s.plan.0.entry("_defaults".into()).or_default();
        d.dataset_rows.insert(source.to_string(), n);
        d.dataset_edits.retain(|e| !matches!(e, Edit::Tag { dataset, .. } if dataset == source));
        d.dataset_edits.push(Edit::Tag { dataset: source.to_string(), fields: tag_fields(&app.manifest, source) });
        return Some(s);
    }
    let mut s = crate::scale::apply(app, &s, &Knob::HostList(source.to_string()), n as u64).ok()?;
    let list = s.plan.0.get_mut(source)?.response.ret.as_mut().and_then(items_mut)?;
    for (i, item) in list.iter_mut().enumerate() {
        mark(item, &token(source, &i.to_string()));
    }
    Some(s)
}

/// Request variants that ask for `n` records: numbers in the request and
/// common count keys of its key-value lists, within what the platform lets through.
fn asking(app: &App, spec: &RunSpec, n: u64) -> Vec<RunSpec> {
    let (knobs, pair_lists) = crate::scale::request_knobs(&spec.args);
    let mut paths: Vec<String> = knobs.into_iter().filter_map(|k| if let Knob::Field(p) = k { Some(p) } else { None }).collect();
    for list in &pair_lists {
        paths.extend(COUNT_KEYS.iter().map(|k| format!("{list}.{k}")));
    }
    // A `wasi:http` request carries its query in the URL.
    if spec.args.first().and_then(|a| a.get("uri")).is_some_and(Value::is_string) {
        paths.extend(COUNT_KEYS.iter().map(|k| format!("uri?{k}")));
    }
    let mut out: Vec<RunSpec> = Vec::new();
    for path in paths {
        for v in [n, 1_000_000] {
            let mut s = spec.clone();
            let (i, p) = crate::scale::split_arg(&path);
            let Some(a) = s.args.get_mut(i) else { continue };
            let set = match crate::harness::field(a, p) {
                Some(Value::Number(_)) => crate::harness::field_mut(a, p).map(|x| *x = json!(v)).is_some(),
                _ => crate::scale::set_text(a, p, &v.to_string()).is_ok(),
            };
            if set && crate::constraints::conform_request_typed(&mut s.args, app, &s.export, s.seed).is_ok() && !out.iter().any(|o| o.args == s.args) {
                out.push(s);
            }
        }
    }
    out
}

/// Counts the records that leave: each collection the app may read, at
/// one more record than its limit and at twice the limit (without one, at
/// `NO_CAP_ROWS`), from the request and the pages it links to. Where a
/// limit holds, request fields that may ask for more.
pub fn probe(app: &App, base: &RunSpec, run: Runner) -> Probe {
    let m = &app.manifest;
    let mut report = Probe::default();
    // Collections: datasets the app queries (a page counts as much as a
    // list), and host lists without a dataset.
    let lists = crate::scale::list_functions(app);
    let mut sources: Vec<(String, bool)> = Vec::new();
    for f in app.imports.iter().filter(|i| i.kind == crate::wit::ImportKind::Platform).flat_map(|i| i.funcs.iter()) {
        match m.function(&f.key).and_then(|x| x.query.as_ref()) {
            Some(q) if q.one => {}
            Some(q) => {
                let d = &m.datasets[&q.dataset];
                if tag_fields(m, &q.dataset).is_empty() && !d.template[&d.key].is_string() {
                    report.not_counted.push(q.dataset.clone());
                } else if !sources.iter().any(|(s, _)| *s == q.dataset) {
                    sources.push((q.dataset.clone(), true));
                }
            }
            None if lists.contains(&f.key) => sources.push((f.key.clone(), false)),
            None => {}
        }
    }
    report.not_counted.sort();
    report.not_counted.dedup();
    if sources.is_empty() {
        return report;
    }
    let starts = starts(app, base, run);
    let mut specs: Vec<RunSpec> = Vec::new();
    let mut lifting: Vec<RunSpec> = Vec::new();
    for (source, dataset) in &sources {
        let cap = cap(m, dataset.then_some(source.as_str()));
        let max = crate::dataset::MAX_ROWS as u64;
        let sizes: Vec<usize> = match cap {
            Some(c) => [(c + 1).min(max), (2 * c).min(max)].into_iter().collect::<BTreeSet<_>>().into_iter().map(|n| n as usize).collect(),
            None => vec![NO_CAP_ROWS],
        };
        for start in &starts {
            for &n in &sizes {
                let Some(s) = marked(app, start, source, *dataset, n) else { continue };
                if cap.is_some() && n == *sizes.last().unwrap_or(&0) {
                    lifting.extend(asking(app, &s, n as u64));
                }
                specs.push(s);
            }
        }
    }
    lifting.truncate(MAX_FIELD_RUNS);
    specs.extend(lifting);
    let runs = par::map(&specs, |s| run(s));
    report.runs = runs.len();
    let mut bounds: BTreeMap<String, Bound> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for r in &runs {
        if let Some(counter) = Counter::for_run(&r.spec, m)
            && r.outcome.kind == OutcomeKind::Ok
        {
            for (place, counts) in counter.places(r, m) {
                for s in &counter.sources {
                    let b = bounds.entry(s.name.clone()).or_insert_with(|| Bound {
                        source: s.name.clone(),
                        dataset: s.dataset,
                        cap: s.cap,
                        total: 0,
                        most: BTreeMap::new(),
                    });
                    b.total = b.total.max(s.total);
                    let n = counts.get(&s.name).copied().unwrap_or(0) as usize;
                    let most = b.most.entry(place.clone()).or_default();
                    *most = (*most).max(n);
                }
            }
        }
        for f in crate::detect::per_run_checked(app, r) {
            if f.kind == "mass_disclosure" && seen.insert(f.id.clone()) {
                report.findings.push(f);
            }
        }
    }
    for b in bounds.values_mut() {
        b.most.retain(|_, n| *n > 0);
    }
    report.bounds = bounds.into_values().collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{HostCall, Outcome, Totals};

    fn manifest(extra: &str) -> Manifest {
        toml::from_str(&format!(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            output = {{ status = "status", body = "body" }}
            [datasets.customers]
            rows = 3
            key = "id"
            template = {{ id = 1, name = "Customer", email = "c@mail.example", status = "open" }}
            [functions."x:y/customers#all"]
            query = {{ dataset = "customers", filter = {{ status = "status" }} }}
            {extra}
            "#
        ))
        .unwrap()
    }

    fn run(m: &Manifest, rows: usize, body: &str, events: Vec<HostCall>) -> RunRecord {
        let mut spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![json!({})],
            plan: Default::default(),
            now: String::new(),
            seed: 0,
            fuel: 0,
            memory: 0,
            ns_per_fuel: 0.0,
        };
        let d = spec.plan.0.entry("_defaults".into()).or_default();
        d.dataset_rows.insert("customers".into(), rows);
        d.dataset_edits.push(Edit::Tag { dataset: "customers".into(), fields: tag_fields(m, "customers") });
        RunRecord {
            id: "r1".into(),
            spec,
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(json!({"status": 200, "body": body})),
            totals: Totals::default(),
            events,
            guest_error: None,
            rejected_output: None,
            command_exit_code: None,
            memory_limit_hit: false,
            capture_limited: false,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// The page an app makes of customers `ids`: name and email of each.
    fn page(ids: impl IntoIterator<Item = usize>) -> String {
        ids.into_iter()
            .map(|i| {
                let t = token("customers", &i.to_string());
                format!("<li>Customer {t}: c+{t}@mail.example</li>")
            })
            .collect()
    }

    #[test]
    fn marks_keep_addresses_addresses() {
        let mut v = json!({"name": "Ada", "email": "ada@mail.example", "n": 3});
        mark(&mut v, "rtok");
        assert_eq!(v, json!({"name": "Ada rtok", "email": "ada+rtok@mail.example", "n": 3}));
    }

    #[test]
    fn fields_a_query_filters_on_stay_unmarked() {
        let m = manifest("");
        assert_eq!(tag_fields(&m, "customers"), ["name", "email"]);
        let m = manifest("values = { email = \"format:email\" }");
        assert_eq!(tag_fields(&m, "customers"), ["name"]);
    }

    #[test]
    fn more_records_than_the_limit_in_one_place_is_mass_disclosure() {
        let m = manifest("[limits]\nrecords_per_response = 2");
        let f = check(&run(&m, 3, &page(1..=3), vec![]), &m);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].kind.as_str(), f[0].severity), ("mass_disclosure", Severity::Fail));
        assert_eq!(f[0].title, "h puts 3 of 3 customers records into the response; the platform allows 2 per response");
        // Up to the limit is fine, and so is a token inside a longer word.
        assert!(check(&run(&m, 3, &page(1..=2), vec![]), &m).is_empty());
        let glued = format!("{}{}x", page(1..=2), token("customers", "3"));
        assert!(check(&run(&m, 3, &glued, vec![]), &m).is_empty());
        // Calls that send data out count, with what the harness counted.
        let m = manifest("[limits]\nrecords_per_response = 2\n[functions.\"x:y/mail#send\"]\neffect = \"external\"");
        let send = HostCall { n: 1, func: "x:y/mail#send".into(), records: [("customers".to_string(), 3)].into(), ..Default::default() };
        let f = check(&run(&m, 3, "<p>Sent</p>", vec![send]), &m);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].title.ends_with("into calls to x:y/mail#send; the platform allows 2 per response"), "{}", f[0].title);
    }

    #[test]
    fn a_whole_collection_without_a_limit_is_a_hint_or_with_personal_data_a_warning() {
        let m = manifest("");
        let n = NO_CAP_MIN;
        let f = check(&run(&m, n, &page(1..=n), vec![]), &m);
        assert_eq!(f.iter().map(|f| f.severity).collect::<Vec<_>>(), [Severity::Info], "{f:?}");
        assert!(check(&run(&m, n, &page(2..=n), vec![]), &m).is_empty());
        let m = manifest("result = { email = \"pii\" }");
        let f = check(&run(&m, n, &page(1..=n), vec![]), &m);
        assert_eq!(f.iter().map(|f| f.severity).collect::<Vec<_>>(), [Severity::Warn], "{f:?}");
        assert_eq!(f[0].title, format!("h puts all {n} customers records into the response; no limit per response is declared"));
    }

    #[test]
    fn tagged_worlds_mark_each_record() {
        let m = manifest("");
        let r = run(&m, 2, "", vec![]);
        let state = crate::harness::initial_state(&m, &r.spec.plan, 0).unwrap();
        let t = token("customers", "2");
        assert_eq!(state.tables["customers"][1], json!({"id": 2, "name": format!("Customer {t}"), "email": format!("c+{t}@mail.example"), "status": "open"}));
    }
}
