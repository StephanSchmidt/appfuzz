//! Shrinking a run spec to a small one that still shows a finding.
//!
//! Greedy: candidates come biggest step first, and the first one that
//! still shows the finding becomes the new spec. A candidate that failed
//! is never tried again (runs are pure, so it fails again). Numbers and
//! lengths go down in halving steps (n - d for d = n/2, n/4, …, 1), which
//! ends at the smallest value that still shows it: the boundary.
//!
//! Findings from comparing runs (scale, metamorphic pairs) shrink too:
//! the test reruns the comparison on each candidate.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::detect::Finding;
use crate::fuzz::{first_list, first_list_mut, nodes};
use crate::harness::{App, set_clock_fields};
use crate::metamorphic::{self, Change};
use crate::par::{self, Runner};
use crate::plan::{FnPlan, Response};
use crate::record::{OutcomeKind, RunRecord, RunSpec};
use crate::scale::{self, Knob};
use crate::value::GenOpts;

/// Lists at most this long get their elements simplified.
const LEAF_LIST: usize = 8;
/// Chunk removals per list and pass.
const CHUNKS: usize = 32;

/// Shrinks a spec while `keeps` holds for its run. Returns the smallest
/// spec found and the runs it took. `base` is the example request:
/// fields move back to it.
pub fn minimise(app: &App, spec: &RunSpec, base: &[Value], keeps: &(dyn Fn(&RunRecord) -> bool + Sync), max_runs: u32, run: Runner) -> (RunSpec, u32) {
    shrink(app, spec, base, &|c| keeps(&run(c)), max_runs)
}

/// Shrinks a spec while `test` holds, trying at most `max_tests`
/// candidates. Returns the smallest spec and the candidates tried.
pub fn shrink(app: &App, spec: &RunSpec, base: &[Value], test: &(dyn Fn(&RunSpec) -> bool + Sync), max_tests: u32) -> (RunSpec, u32) {
    // Candidates are tried a chunk at a time on all threads; the first one
    // that keeps the finding (in order) wins, as if tried one by one.
    let mut cur = spec.clone();
    let mut tried: HashSet<blake3::Hash> = HashSet::from([key(&cur)]);
    // Per number: the largest value known not to show it. Steps down
    // start above it, so a boundary takes log n tests, not log² n.
    let mut lows: Lows = HashMap::new();
    let mut tests = 0;
    'outer: loop {
        let cands: Vec<Cand> = candidates(app, &cur, base, &lows).into_iter().filter(|c| tried.insert(key(&c.spec))).collect();
        for chunk in cands.chunks(par::jobs().max(1)) {
            let chunk = &chunk[..chunk.len().min(max_tests.saturating_sub(tests) as usize)];
            if chunk.is_empty() {
                break 'outer;
            }
            tests += chunk.len() as u32;
            let ok = par::map(chunk, |c| test(&c.spec));
            let win = ok.iter().position(|k| *k);
            for c in &chunk[..win.unwrap_or(chunk.len())] {
                if let Some((k, v)) = &c.step {
                    let low = lows.entry(k.clone()).or_insert(*v);
                    *low = (*low).max(*v);
                }
            }
            if let Some(i) = win {
                // Another change can move every boundary.
                if chunk[i].step.is_none() {
                    lows.clear();
                }
                cur = chunk[i].spec.clone();
                continue 'outer;
            }
        }
        break;
    }
    (cur, tests)
}

type Lows = HashMap<String, u64>;

/// A candidate, and the number it sets if it steps one down.
struct Cand {
    spec: RunSpec,
    step: Option<(String, u64)>,
}

impl From<RunSpec> for Cand {
    fn from(spec: RunSpec) -> Self {
        Cand { spec, step: None }
    }
}

/// `smaller(n, floor)`, above the largest value known not to work.
fn down(n: u64, floor: u64, key: &str, lows: &Lows) -> Vec<u64> {
    smaller(n, lows.get(key).map_or(floor, |l| floor.max(l + 1)))
}

fn key(s: &RunSpec) -> blake3::Hash {
    blake3::hash(&serde_json::to_vec(s).unwrap_or_default())
}

/// Bytes of what a reader of a case has to read: request and plan.
pub fn size(s: &RunSpec) -> usize {
    serde_json::to_vec(&(&s.args, &s.plan)).map_or(0, |b| b.len())
}

/// Bytes of the plan alone: where unshrunk host data shows.
pub fn plan_size(s: &RunSpec) -> usize {
    serde_json::to_vec(&s.plan).map_or(0, |b| b.len())
}

/// How a finding from comparing runs is shown again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Across {
    /// One exact function occurrence, with a transient failure or an outage.
    Fault { fault: crate::faults::Recipe },
    /// Turn a knob over sizes (`appfuzz scale`).
    /// `context`: the mode it was turned in, which the spec sets.
    Scale { knob: Knob, sizes: Vec<u64>, context: Option<String> },
    /// Turn two knobs together: calls to `func` for each pair of elements
    /// (`appfuzz amplify`).
    Nested { func: String, outer: Knob, inner: Knob },
    /// Run a variant of the run and compare (`appfuzz probe pairs`).
    Pair { change: Change, func: Option<String> },
    /// Forged credentials, a secret's prefixes or other random seeds
    /// (`appfuzz probe auth`).
    Auth { auth: crate::auth::Recipe },
}

impl Across {
    /// How `f` was found, if it came from comparing runs this way.
    pub fn of(f: &Finding) -> Option<Across> {
        if let Some(auth) = f.detail.get("auth") {
            return serde_json::from_value(auth.clone()).ok().map(|auth| Across::Auth { auth });
        }
        if let Some(fault) = f.detail.get("fault") {
            return serde_json::from_value(fault.clone()).ok().map(|fault| Across::Fault { fault });
        }
        if let (Some(func), Some([outer, inner])) =
            (f.detail.get("func").and_then(Value::as_str), f.detail.get("knobs").and_then(Value::as_array).map(Vec::as_slice))
        {
            let (outer, inner) = (serde_json::from_value(outer.clone()).ok()?, serde_json::from_value(inner.clone()).ok()?);
            return Some(Across::Nested { func: func.to_string(), outer, inner });
        }
        if let Some(k) = f.detail.get("knob") {
            let knob: Knob = serde_json::from_value(k.clone()).ok()?;
            let sizes = scale::default_sizes(&knob);
            let context = f.detail.get("context").and_then(Value::as_str).map(str::to_string);
            return Some(Across::Scale { knob, sizes, context });
        }
        let change: Change = serde_json::from_value(f.detail.get("change")?.clone()).ok()?;
        let func = f.detail.get("func").and_then(Value::as_str).map(str::to_string);
        Some(Across::Pair { change, func })
    }

    /// The run `f` was found from: the base of a pair, else `f`'s run.
    pub fn start_run<'a>(&self, f: &'a Finding) -> Option<&'a str> {
        match self {
            Across::Pair { .. } | Across::Fault { .. } | Across::Auth { .. } => f.detail.get("base_run").and_then(Value::as_str),
            Across::Scale { .. } | Across::Nested { .. } => f.run.as_deref(),
        }
    }

    /// The finding with this id, if comparing runs from `spec` shows it.
    pub fn shows(&self, app: &App, id: &str, spec: &RunSpec, run: Runner) -> Option<Finding> {
        self.evaluate(app, id, spec, run).ok().flatten()
    }

    pub fn evaluate(&self, app: &App, id: &str, spec: &RunSpec, run: Runner) -> anyhow::Result<Option<Finding>> {
        Ok(match self {
            Across::Fault { fault } => {
                let base = run(spec);
                if base.outcome.kind != OutcomeKind::Ok {
                    return Ok(None);
                }
                let Some(variant) = fault.variant(app, &base) else {
                    return Ok(None);
                };
                let actual = run(&variant.spec);
                crate::faults::compare(app, &base, fault, &variant, &actual).into_iter().find(|f| f.matches_id(id))
            }
            Across::Scale { knob, sizes, context } => {
                let found = scale::scale(app, spec, knob.clone(), sizes, run)?.findings.into_iter();
                found
                    .map(|f| match context {
                        Some(c) => scale::in_context(f, c),
                        None => f,
                    })
                    .find(|f| f.matches_id(id))
            }
            Across::Nested { func, outer, inner } => scale::nested_again(app, spec, func, outer, inner, run).filter(|f| f.matches_id(id)),
            Across::Pair { change, func } => {
                let r = run(spec);
                let vs: Vec<_> = metamorphic::variants(app, &r).into_iter().filter(|v| v.change == *change && v.func == *func).collect();
                vs.iter().find_map(|v| metamorphic::compare(app, &r, v, &run(&v.spec)).into_iter().find(|f| f.matches_id(id)))
            }
            Across::Auth { auth } => crate::probe::auth_again(app, auth, spec, run).into_iter().find(|f| f.matches_id(id)),
        })
    }

    /// Runs one test costs.
    pub fn runs_per_test(&self) -> u32 {
        match self {
            Across::Scale { sizes, .. } => sizes.len().max(1) as u32,
            Across::Pair { .. } | Across::Fault { .. } => 2,
            Across::Nested { .. } => 4,
            Across::Auth { auth } => auth.runs(),
        }
    }

    pub fn describe(&self) -> Value {
        match self {
            Across::Fault { fault } => json!({"fault": fault}),
            Across::Scale { knob, sizes, context } => json!({"scale": knob, "sizes": sizes, "context": context}),
            Across::Nested { func, outer, inner } => json!({"nested": [outer, inner], "func": func}),
            Across::Pair { change, func } => json!({"variant": {"change": change, "func": func}}),
            Across::Auth { auth } => json!({"auth": auth}),
        }
    }
}

/// n - d for d = n - floor, (n - floor)/2, …, 1: the floor first, then
/// ever smaller steps down.
fn smaller(n: u64, floor: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut d = n.saturating_sub(floor);
    while d > 0 {
        out.push(n - d);
        d /= 2;
    }
    out
}

/// Smaller variants of a spec, biggest steps first: across the whole
/// spec, every big step comes before any small one.
fn candidates(app: &App, s: &RunSpec, base: &[Value], lows: &Lows) -> Vec<Cand> {
    let mut tiers: [Vec<Cand>; TIERS] = Default::default();
    let start = app.manifest.start_time();
    let entry = app.manifest.entry.as_ref();
    // The clock at the start, and request fields filled from the clock
    // as it says (the fuzzer may have set them to anything).
    for now in [start.clone(), s.now.clone()] {
        let mut c = s.clone();
        c.now = now.clone();
        if let (Some(e), Some(a)) = (entry, c.args.first_mut()) {
            set_clock_fields(a, &e.fields, &now);
        }
        if c != *s {
            tiers[0].push(c.into());
        }
    }
    if s.seed != 1 {
        tiers[0].push(RunSpec { seed: 1, ..s.clone() }.into());
    }
    for k in s.plan.0.keys() {
        let mut c = s.clone();
        c.plan.0.remove(k);
        tiers[0].push(c.into());
    }
    for (name, definition) in &app.manifest.datasets {
        let n = s.plan.0.get("_defaults").and_then(|p| p.dataset_rows.get(name)).copied().unwrap_or(definition.rows);
        let at = format!("dataset_rows:{name}");
        for m in down(n as u64, 0, &at, lows) {
            let mut c = s.clone();
            c.plan.0.entry("_defaults".into()).or_default().dataset_rows.insert(name.clone(), m as usize);
            tiers[1].push(Cand { spec: c, step: Some((at.clone(), m)) });
        }
    }
    for (k, fp) in &s.plan.0 {
        let with = |f: &dyn Fn(&mut FnPlan)| {
            let mut c = s.clone();
            f(c.plan.0.get_mut(k).expect("key"));
            Cand::from(c)
        };
        if fp.on_call.len() > 1 {
            tiers[0].push(with(&|p| p.on_call.clear()));
        }
        if fp.rules.len() > 1 {
            tiers[0].push(with(&|p| p.rules.clear()));
        }
        for n in fp.on_call.keys() {
            tiers[1].push(with(&|p| {
                p.on_call.remove(n);
            }));
            if let Some((start, tail)) = crate::plan::call_start(n) {
                let key = format!("{k}\0call:{n}");
                for m in down(start as u64, 1, &key, lows) {
                    let next = format!("{m}{}", if tail { "+" } else { "" });
                    if fp.on_call.contains_key(&next) {
                        continue;
                    }
                    let mut candidate = with(&|p| {
                        if let Some(response) = p.on_call.remove(n) {
                            p.on_call.insert(next.clone(), response);
                        }
                    });
                    candidate.step = Some((key.clone(), m));
                    tiers[1].push(candidate);
                }
            }
        }
        for i in 0..fp.rules.len() {
            tiers[1].push(with(&|p| {
                p.rules.remove(i);
            }));
        }
        if fp.default.is_some() {
            tiers[1].push(with(&|p| p.default = None));
        }
        if fp.cost.is_some() {
            tiers[1].push(with(&|p| p.cost = None));
        }
        // Every response of the function: its own, per call, the default,
        // per rule.
        let mut slots: Vec<(Slot, &Response)> = vec![(Slot::Own, &fp.response)];
        slots.extend(fp.on_call.iter().map(|(n, r)| (Slot::Call(n.clone()), r)));
        slots.extend(fp.default.iter().map(|r| (Slot::Default, r)));
        slots.extend(fp.rules.iter().enumerate().map(|(i, r)| (Slot::Rule(i), &r.response)));
        for (slot, r) in slots {
            let at = format!("{k}\0{slot:?}");
            for (tier, edit, step) in response_edits(r, &at, lows) {
                let mut c = with(&|p| {
                    if let Some(r) = slot.get(p) {
                        edit(r);
                    }
                });
                c.step = step;
                tiers[tier].push(c);
            }
        }
    }
    request_edits(app, s, base, lows, &mut tiers[2]);
    tiers.into_iter().flatten().collect()
}

#[derive(Clone, Debug)]
enum Slot {
    Own,
    Call(String),
    Default,
    Rule(usize),
}

impl Slot {
    fn get<'a>(&self, p: &'a mut FnPlan) -> Option<&'a mut Response> {
        match self {
            Slot::Own => Some(&mut p.response),
            Slot::Call(n) => p.on_call.get_mut(n),
            Slot::Default => p.default.as_mut(),
            Slot::Rule(i) => p.rules.get_mut(*i).map(|r| &mut r.response),
        }
    }
}

type Edit = Box<dyn Fn(&mut Response)>;
/// Tiers of steps: whole entries, single entries and literal lists made
/// generated, finer edits, single values.
const TIERS: usize = 4;

/// An edit with its tier and the number it steps down.
type Step = (usize, Edit, Option<(String, u64)>);

/// Smaller variants of one response, each with its tier and the number
/// it steps down (`at` names the response).
fn response_edits(r: &Response, at: &str, lows: &Lows) -> Vec<Step> {
    let mut edits: Vec<(usize, Edit)> = Vec::new();
    let mut steps: Vec<Step> = Vec::new();
    let out = &mut edits;
    if let Some(v) = &r.ret {
        let mut structured_bytes = 1024 * 1024;
        let mut structured_edits = 0;
        'structured: for path in crate::structured::locations(v) {
            for text in crate::structured::shrink(v.pointer(&path).and_then(Value::as_str).expect("string")) {
                if structured_edits == 32 || text.len() > structured_bytes {
                    break 'structured;
                }
                structured_edits += 1;
                structured_bytes -= text.len();
                let path = path.clone();
                out.push((
                    2,
                    Box::new(move |r| {
                        if let Some(slot) = r.ret.as_mut().and_then(|v| v.pointer_mut(&path)) {
                            *slot = json!(text);
                        }
                    }),
                ));
            }
        }
        // A literal list whose content does not matter: generated
        // values of the same length read in one line.
        if let Some(a) = first_list(v) {
            let len = a.len();
            let ok = matches!(v, Value::Object(o) if o.contains_key("ok"));
            let some = !v.is_array() && !ok;
            out.push((
                1,
                Box::new(move |r| {
                    r.ret = None;
                    r.generate =
                        Some(GenOpts { list_len: Some(len), results: ok.then(|| "ok".into()), options: some.then(|| "some".into()), ..Default::default() });
                }),
            ));
        }
        // Without it, generated values (or the function's own plan).
        out.push((1, Box::new(|r| r.ret = None)));
        if let Some(a) = first_list(v) {
            list_edits(a, out);
        }
    }
    if let Some(g) = &r.generate {
        out.push((1, Box::new(|r| r.generate = None)));
        if let Some(n) = g.list_len {
            // Unset: the default lengths (meaningless on a function
            // that returns no list).
            out.push((
                2,
                Box::new(|r| {
                    if let Some(g) = &mut r.generate {
                        g.list_len = None;
                    }
                }),
            ));
            let key = format!("{at}\0list_len");
            for m in down(n as u64, 0, &key, lows) {
                let f: Edit = Box::new(move |r| {
                    if let Some(g) = &mut r.generate {
                        g.list_len = Some(m as usize);
                    }
                });
                steps.push((2, f, Some((key.clone(), m))));
            }
        }
        type Clear = fn(&mut GenOpts);
        let fields: [(bool, Clear); 5] = [
            (g.strings.is_some(), |g| g.strings = None),
            (g.numbers.is_some(), |g| g.numbers = None),
            (g.results.is_some(), |g| g.results = None),
            (g.options.is_some(), |g| g.options = None),
            (g.seed.is_some(), |g| g.seed = None),
        ];
        for (_, f) in fields.into_iter().filter(|(on, _)| *on) {
            out.push((
                2,
                Box::new(move |r| {
                    if let Some(g) = &mut r.generate {
                        f(g);
                    }
                }),
            ));
        }
    }
    if r.latency_ms.is_some() {
        out.push((2, Box::new(|r| r.latency_ms = None)));
    }
    edits.into_iter().map(|(t, e)| (t, e, None)).chain(steps).collect()
}

/// Text with a run of one character (`aaaa…`, as the fuzzer makes long
/// text) left out or halved, where what matters comes after it. Cutting
/// anywhere else would only mangle the text (a URL's host, a word).
fn run_cuts(t: &str) -> Vec<String> {
    let chars: Vec<char> = t.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() && out.len() < CHUNKS {
        let end = at + chars[at..].iter().take_while(|c| **c == chars[at]).count();
        if end - at >= 8 {
            for keep in [0, (end - at) / 2] {
                out.push(chars[..at + keep].iter().chain(&chars[end..]).collect());
            }
        }
        at = end;
    }
    out
}

/// Removes chunks of a literal list (halves, quarters, … single
/// elements), then simplifies the elements of a short one.
fn list_edits(a: &[Value], out: &mut Vec<(usize, Edit)>) {
    let len = a.len();
    let mut size = len / 2;
    let mut n = 0;
    while size > 0 && n < CHUNKS {
        let mut at = 0;
        while at < len && n < CHUNKS {
            let (from, to) = (at, (at + size).min(len));
            out.push((
                2,
                Box::new(move |r| {
                    if let Some(a) = r.ret.as_mut().and_then(first_list_mut) {
                        a.drain(from..to.min(a.len()));
                    }
                }),
            ));
            at += size;
            n += 1;
        }
        size /= 2;
    }
    if len == 1 {
        out.push((
            2,
            Box::new(|r| {
                if let Some(a) = r.ret.as_mut().and_then(first_list_mut) {
                    a.clear();
                }
            }),
        ));
    }
    if len > LEAF_LIST {
        return;
    }
    let mut ptrs = Vec::new();
    for (i, x) in a.iter().enumerate() {
        nodes(x, format!("/{i}"), &mut ptrs);
    }
    let root = Value::Array(a.to_vec());
    for p in ptrs {
        let Some(node) = root.pointer(&p) else { continue };
        let variants: Vec<Value> = match node {
            Value::Number(n) => n.as_u64().map(|n| smaller(n, 0).into_iter().map(|m| json!(m)).collect()).unwrap_or_default(),
            Value::String(t) if t.chars().count() > 1 => vec![json!(t.chars().take(t.chars().count() / 2).collect::<String>()), json!("a")],
            _ => vec![],
        };
        for v in variants {
            let p = p.clone();
            out.push((
                3,
                Box::new(move |r| {
                    if let Some(a) = r.ret.as_mut().and_then(first_list_mut) {
                        let mut tmp = Value::Array(std::mem::take(a));
                        if let Some(s) = tmp.pointer_mut(&p) {
                            *s = v.clone();
                        }
                        if let Value::Array(x) = tmp {
                            *a = x;
                        }
                    }
                }),
            ));
        }
    }
}

/// Request fields back to the example, shorter lists and text, smaller
/// numbers.
fn request_edits(app: &App, s: &RunSpec, base: &[Value], lows: &Lows, out: &mut Vec<Cand>) {
    let mut ptrs = Vec::new();
    for (i, a) in s.args.iter().enumerate() {
        nodes(a, format!("/{i}"), &mut ptrs);
    }
    let root = Value::Array(s.args.clone());
    let base_root = Value::Array(base.to_vec());
    let clock: HashSet<String> = app.manifest.entry.iter().flat_map(|e| e.fields.keys()).map(|k| format!("/0/{}", k.replace('.', "/"))).collect();
    let mut structured_bytes = 1024 * 1024;
    let mut structured_edits = 0;
    for p in ptrs {
        let Some(node) = root.pointer(&p) else { continue };
        if clock.contains(&p) {
            continue;
        }
        let mut variants: Vec<(Value, Option<(String, u64)>)> = Vec::new();
        // Back to the example request's value. Text that has it stays as
        // the example has it: cut further, it would only be harder to read.
        // (Numbers and lists go on down to their boundary.)
        match base_root.pointer(&p) {
            Some(b) if b == node && node.as_str().is_some_and(|t| t.parse::<u64>().is_err()) => continue,
            Some(b) if b != node => variants.push((b.clone(), None)),
            _ => {}
        }
        let len_key = format!("{p}\0len");
        let num = |n: u64, text: bool| -> Vec<(Value, Option<(String, u64)>)> {
            down(n, 1, &p, lows).into_iter().map(|m| (if text { json!(m.to_string()) } else { json!(m) }, Some((p.clone(), m)))).collect()
        };
        variants.extend(match node {
            Value::Array(a) if !a.is_empty() => {
                let mut v = vec![(Value::Array(a[..a.len() / 2].to_vec()), None)];
                v.extend((0..a.len().min(8)).map(|i| {
                    let mut b = a.clone();
                    b.remove(i);
                    (Value::Array(b), None)
                }));
                v
            }
            Value::String(t) => {
                let mut inner = Vec::new();
                if structured_edits < 32 && structured_bytes > 0 {
                    for text in crate::structured::shrink(t) {
                        if structured_edits == 32 || text.len() > structured_bytes {
                            break;
                        }
                        structured_edits += 1;
                        structured_bytes -= text.len();
                        inner.push((json!(text), None));
                    }
                }
                // A canary the finding doesn't need goes as a whole.
                inner.extend(crate::output::without_canaries(t).into_iter().map(|text| (json!(text), None)));
                inner.extend(match t.parse::<u64>() {
                    Ok(n) => num(n, true),
                    // Only long text is cut, to no less than 16 characters:
                    // short text is a word that matters.
                    Err(_) => down(t.chars().count() as u64, 16, &len_key, lows)
                        .into_iter()
                        .map(|n| (json!(t.chars().take(n as usize).collect::<String>()), Some((len_key.clone(), n))))
                        .chain(run_cuts(t).into_iter().map(|t| (json!(t), None)))
                        .collect(),
                });
                inner
            }
            Value::Number(n) => n.as_u64().map(|n| num(n, false)).unwrap_or_default(),
            _ => vec![],
        });
        for (v, step) in variants {
            let mut r = root.clone();
            if let Some(slot) = r.pointer_mut(&p) {
                *slot = v;
            }
            if let Value::Array(args) = r {
                out.push(Cand { spec: RunSpec { args, ..s.clone() }, step });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_findings_repeat_their_probe() {
        let found = crate::detect::Finding::new("timing_unsafe_compare", "x", crate::detect::Severity::Warn, "t".into(), json!({}), Some("r2"));
        let f = crate::auth::Recipe::Timing { forged: "a made-up API key".into() }.mark(found, "r1");
        let a = Across::of(&f).unwrap();
        assert_eq!(a.start_run(&f), Some("r1"));
        assert_eq!(a.runs_per_test(), 27);
        let back: Across = serde_json::from_value(serde_json::to_value(&a).unwrap()).unwrap();
        assert_eq!(back.describe(), json!({"auth": {"check": "timing", "forged": "a made-up API key"}}));
    }

    #[test]
    fn canaries_go_whole() {
        let uri = "https://app.example/cnry278d2<i>'\"../;$(x)?name=cnry3b543<i>'\"&u=https://cnry1a2b7.example/";
        assert_eq!(
            crate::output::without_canaries(uri),
            [
                "https://app.example/?name=cnry3b543<i>'\"&u=https://cnry1a2b7.example/",
                "https://app.example/cnry278d2<i>'\"../;$(x)?name=&u=https://cnry1a2b7.example/",
                "https://app.example/cnry278d2<i>'\"../;$(x)?name=cnry3b543<i>'\"&u=",
            ]
        );
    }

    #[test]
    fn runs_of_one_character_shrink() {
        let t = format!("https://app.example/{}?url={}x", "a".repeat(32), "b".repeat(8));
        assert_eq!(
            run_cuts(&t),
            [
                "https://app.example/?url=bbbbbbbbx".to_string(),
                format!("https://app.example/{}?url=bbbbbbbbx", "a".repeat(16)),
                format!("https://app.example/{}?url=x", "a".repeat(32)),
                format!("https://app.example/{}?url=bbbbx", "a".repeat(32)),
            ]
        );
        assert!(run_cuts("https://app.example/?q=shoes").is_empty());
    }

    #[test]
    fn steps_down() {
        assert_eq!(smaller(50, 0), vec![0, 25, 38, 44, 47, 49]);
        assert_eq!(smaller(2, 1), vec![1]);
        assert!(smaller(1, 1).is_empty());
        // Known not to show it at 600: steps start above.
        let lows = Lows::from([("k".to_string(), 600)]);
        assert_eq!(down(1000, 1, "k", &lows), vec![601, 801, 901, 951, 976, 988, 994, 997, 999]);
        assert_eq!(down(1000, 1, "other", &lows)[0], 1);
    }

    #[test]
    fn literal_list_becomes_generated() {
        let r = Response { ret: Some(json!({"ok": [1, 2, 3]})), ..Default::default() };
        let mut c = r.clone();
        (response_edits(&r, "", &Lows::new())[0].1)(&mut c);
        assert_eq!(c.ret, None);
        let g = c.generate.unwrap();
        assert_eq!((g.list_len, g.results.as_deref()), (Some(3), Some("ok")));
    }

    #[test]
    fn removes_chunks() {
        let r = Response { ret: Some(json!([1, 2, 3, 4])), ..Default::default() };
        let got: Vec<Value> = response_edits(&r, "", &Lows::new())
            .iter()
            .map(|(_, e, _)| {
                let mut c = r.clone();
                e(&mut c);
                c.ret.unwrap_or(Value::Null)
            })
            .collect();
        assert!(got.contains(&json!([3, 4])) && got.contains(&json!([1, 2])) && got.contains(&json!([1, 3, 4])));
        // Elements simplified: numbers down.
        assert!(got.contains(&json!([0, 2, 3, 4])));
    }
}
