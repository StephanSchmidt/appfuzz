//! The fuzz suite: one engine, every per-run detector on every run.
//!
//! A corpus of inputs (request + host plan + clock + seed). An input is
//! kept when its run shows new behaviour (features: call sites reached,
//! host-call order, result shapes, call-count buckets, output tags, URLs,
//! outcome, panic location) or a new maximum of a resource (calls per host
//! function, fuel, memory, output bytes, bytes sent to the host, virtual
//! time, cost, call depth). Stages mutate a parent from the corpus; a
//! scheduler favours the stages that keep finding things.
//!
//! One worker per thread, each with its own random generator: it picks a
//! parent and a stage from the shared state, then mutates, runs, detects
//! and extracts features on its own, and takes the lock again only to
//! admit the result. With one job a campaign is deterministic; with more,
//! the order of admissions depends on timing (each run still replays).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, panic_text, per_run};
use crate::harness::{App, field, fn_key_eq, set_clock_fields};
use crate::assertion::{Assertion, Margin, Verdict};
use crate::check::Property;
use crate::metamorphic;
use crate::par;
use crate::plan::{Plan, Response};
use crate::probe::EDGE_TIMES;
use crate::record::{OutcomeKind, RunRecord, RunSpec};
use crate::scale::{self, compare_constants, dictionary, request_knobs, steady};
use crate::statics::Statics;
use crate::urls;
use crate::value::GenOpts;
use crate::wit::ImportKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The example request, and corpus entries from earlier campaigns.
    Seed,
    /// Follow links and forms in the app's own output.
    Crawl,
    /// Change one request field (numbers, strings, `[key, value]` lists).
    Request,
    /// Change what one host function returns (from its WIT type).
    HostValues,
    /// Substitute observed comparison operands into matching request values.
    Compare,
    /// Preserve JSON/CSV syntax while changing embedded request or host data.
    Structured,
    /// Make a host function return a long list.
    GrowList,
    /// Make a request field big (number or length).
    GrowInput,
    /// Make one host call fail (`err`, `none`, or a trap).
    Fault,
    /// Duplicate, drop or reorder the elements of one host result.
    Permute,
    /// Another clock or seed.
    Env,
    /// Request of one entry with the host plan of another.
    Splice,
    /// Pair checks of a new kept run (`metamorphic`); never picked.
    Check,
}

/// Longest list the permute stage hands back.
const MAX_PERMUTED: usize = 64;

const STAGES: [Stage; 11] =
    [Stage::Crawl, Stage::Request, Stage::Compare, Stage::Structured, Stage::HostValues, Stage::GrowList, Stage::GrowInput, Stage::Fault, Stage::Permute, Stage::Env, Stage::Splice];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub spec: RunSpec,
    pub run: String,
    pub stage: Stage,
    /// Why it was kept: `features 4` or `max calls …`.
    pub reasons: Vec<String>,
    #[serde(default)]
    pub feedback:crate::feedback::Feedback,
    #[serde(skip)]
    record: Option<Arc<RunRecord>>,
    /// Same-host links and form inputs of the record, for crawling;
    /// worked out on first use.
    #[serde(skip)]
    links: OnceLock<(Vec<urls::UrlRef>, Vec<String>)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Corpus {
    pub component: String,
    pub entries: Vec<Entry>,
}

impl Corpus {
    pub fn path(state: &std::path::Path, component: &str) -> std::path::PathBuf {
        state.join("corpus").join(format!("{component}.json"))
    }
    pub fn load(state: &std::path::Path, component: &str) -> anyhow::Result<Corpus> {
        use anyhow::Context;
        let path = Self::path(state, component);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("invalid corpus in {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Corpus { component: component.to_string(), entries: vec![] }),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
    pub fn save(&self, state: &std::path::Path) -> anyhow::Result<()> {
        let p = Self::path(state, &self.component);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        crate::store::write_atomic(&p, &serde_json::to_vec(self)?)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// Run the whole budget.
    Budget,
    /// Stop at the first finding not seen before.
    NewFinding,
    /// Stop when nothing new was kept for `plateau` runs.
    Plateau,
}

#[derive(Debug, Clone)]
pub struct FuzzOpts {
    pub runs: Option<u64>,
    pub time: Option<Duration>,
    pub until: Until,
    pub seed: u64,
    /// Runs without a new corpus entry that count as a plateau.
    pub plateau: u64,
    pub max_corpus: usize,
    pub dict_limit: usize,
    /// Seed with the request keys and modes `amplify` would find.
    pub discover: bool,
    pub internal_feedback:bool,
    /// Checked on every run like a detector (`check_failed`).
    pub property: Option<Property>,
    /// Stop at the first new finding of this kind.
    pub stop_on: Option<String>,
    /// Saved asserts, judged on every run (sampled once judging takes more than a
    /// quarter of worker time). Inputs that bring one closer to breaking are kept.
    pub asserts: Vec<(String, Arc<Assertion>)>,
}

impl Default for FuzzOpts {
    fn default() -> Self {
        FuzzOpts { runs: None, time: Some(Duration::from_secs(60)), until: Until::Budget, seed: 1, plateau: 2000, max_corpus: 300, dict_limit: 200, discover: true, internal_feedback:false, property: None, stop_on: None, asserts: Vec::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StageStat {
    pub runs: u64,
    pub kept: u64,
    pub findings: u64,
    /// Runs whose input did not fit the types (wasted).
    pub invalid: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Maximum {
    pub metric: String,
    pub value: u64,
    pub run: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzReport {
    pub runs: u64,
    /// Runs spent finding request keys and modes before fuzzing.
    pub discovery_runs: u64,
    /// Request keys the app reads (mutated more often).
    pub keys: Vec<String>,
    /// Modes found up front (seeded into the corpus).
    pub modes: Vec<String>,
    pub elapsed_ms: u64,
    pub stopped: String,
    pub corpus: usize,
    pub kept: u64,
    pub features: usize,
    pub stages: BTreeMap<Stage, StageStat>,
    pub maxima: Vec<Maximum>,
    /// All findings observed in this campaign, including previously known ones.
    pub findings: Vec<Finding>,
    pub last_new_at_run: u64,
    pub jobs: usize,
    pub feedback:crate::feedback::Status,
    pub faults: crate::faults::Coverage,
    /// What every saved assert saw in this campaign.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub asserts: Vec<AssertStat>,
    /// Time judging asserts took, in percent of worker time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assert_cost_pct: Option<f64>,
}

/// One assert over a campaign: how runs judged it, the first break, and the
/// closest a holding run came to breaking.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AssertStat {
    pub name: String,
    pub property: String,
    pub evaluated: u64,
    pub holds: u64,
    pub vacuous: u64,
    pub broken: u64,
    pub rejected: u64,
    pub undefined: u64,
    pub errors: u64,
    /// Runs skipped by sampling.
    pub sampled_out: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closest: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
    /// How many times a run came closer to breaking it.
    pub closer: u64,
    #[serde(skip)]
    best: Option<(f64, String)>,
}

/// What one run said about one assert.
struct AssertObs {
    verdict: Verdict,
    margin: Option<Margin>,
}

/// Judges saved asserts per run; samples once judging takes more than a quarter of worker time.
struct Judge<'a> {
    list: &'a [(String, Arc<Assertion>)],
    eval_ns: AtomicU64,
    n: AtomicU64,
    started: Instant,
    jobs: u64,
}

impl Judge<'_> {
    fn sample(&self) -> bool {
        let n = self.n.fetch_add(1, AtomicOrdering::Relaxed);
        self.eval_ns.load(AtomicOrdering::Relaxed) <= self.budget_ns() / 4 || n.is_multiple_of(10)
    }

    /// Worker time so far: wall time times workers.
    fn budget_ns(&self) -> u64 {
        (self.started.elapsed().as_nanos() as u64).saturating_mul(self.jobs).max(1)
    }

    fn judge(&self, r: &RunRecord, m: &crate::manifest::Manifest) -> Vec<AssertObs> {
        let t = Instant::now();
        let mut cache = std::collections::HashMap::new();
        let out = self
            .list
            .iter()
            .map(|(_, a)| match a.values_cached(r, m, &mut cache) {
                Err((binding, reason)) => AssertObs { verdict: Verdict::Undefined { binding, reason }, margin: None },
                Ok(values) => {
                    let (verdict, margin) = a.assess(&values);
                    AssertObs { verdict, margin }
                }
            })
            .collect();
        self.eval_ns.fetch_add(t.elapsed().as_nanos() as u64, AtomicOrdering::Relaxed);
        out
    }
}

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>").unwrap());
static ATTR_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([a-zA-Z_:@][-a-zA-Z0-9_:.@]*)\s*(?:=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?"#).unwrap());
static INPUT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#).unwrap());
static PANIC_AT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"panicked at ([^\s:]+:\d+)").unwrap());

/// Shape of a value, two levels deep: `ok([..])`, `err(s)`, `[]`.
fn shape(v: &Value, depth: u32) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(_) => "b".into(),
        Value::Number(_) => "n".into(),
        Value::String(s) if s.is_empty() => "\"\"".into(),
        Value::String(_) => "s".into(),
        Value::Array(a) if a.is_empty() => "[]".into(),
        Value::Array(_) => "[..]".into(),
        Value::Object(o) if o.len() == 1 && depth > 0 => {
            let (k, x) = o.iter().next().expect("one");
            match k.as_str() {
                "ok" | "err" | "some" => format!("{k}({})", shape(x, depth - 1)),
                _ => "{..}".into(),
            }
        }
        Value::Object(_) => "{..}".into(),
    }
}

fn bucket(n: u32) -> u32 {
    match n {
        0..=3 => n,
        4..=7 => 4,
        8..=15 => 8,
        16..=31 => 16,
        32..=127 => 32,
        _ => 128,
    }
}

/// What a run did, as a set of features.
pub fn features(r: &RunRecord, st: &Statics, app: &App) -> BTreeSet<String> {
    let mut f = BTreeSet::new();
    f.insert(format!("outcome:{:?}", r.outcome.kind));
    if let Some(p) = panic_text(&r.stderr).and_then(|p| PANIC_AT.captures(&p).map(|c| c[1].to_string())) {
        f.insert(format!("panic:{p}"));
    }
    let mut prev = String::from("^");
    for e in &r.events {
        match st.app_frame(&e.stack) {
            Some(fr) => f.insert(format!("site:{}:{:x}", fr.module, fr.offset.unwrap_or(0))),
            None => f.insert(format!("call:{}", e.func)),
        };
        if prev != e.func {
            f.insert(format!("seq:{prev}>{}", e.func));
            prev = e.func.clone();
        }
        let res = match (&e.result, &e.trap) {
            (_, Some(_)) => "trap".to_string(),
            (Some(v), _) => shape(v, 2),
            (None, _) => "-".into(),
        };
        f.insert(format!("res:{}:{res}", e.func));
    }
    for (func, n) in r.call_counts() {
        f.insert(format!("count:{func}:{}", bucket(n)));
    }
    let out = app.manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &r.spec.export)).map(|e| &e.output);
    if let Some(result) = &r.result {
        let body = out.and_then(|o| o.body.as_deref()).and_then(|p| field(result, p));
        match body {
            Some(Value::String(b)) => {
                for t in TAG.captures_iter(b).take(500) {
                    let name = t[1].to_ascii_lowercase();
                    for a in ATTR_NAME.captures_iter(&t[2]) {
                        f.insert(format!("attr:{name}.{}", a[1].to_ascii_lowercase()));
                    }
                    f.insert(format!("tag:{name}"));
                }
            }
            _ => {
                f.insert(format!("ret:{}", shape(result, 2)));
            }
        }
        if let Some(s) = out.and_then(|o| o.status.as_deref()).and_then(|p| field(result, p)) {
            f.insert(format!("status:{s}"));
        }
    }
    for u in urls::extract_output(r, &app.manifest).into_iter().take(100) {
        f.insert(format!("url:{} {}", u.method, u.pattern));
    }
    if r.totals.clock_reads > 0 {
        f.insert("clock".into());
    }
    if r.totals.random_bytes > 0 {
        f.insert("random".into());
    }
    f
}

/// Resource measures of a run; the corpus keeps a new maximum of any.
pub fn metrics(r: &RunRecord) -> Vec<(String, u64)> {
    let mut m: Vec<(String, u64)> = r.call_counts().into_iter().map(|(f, n)| (format!("calls {f}"), n as u64)).collect();
    let arg_bytes: usize = r.events.iter().map(|e| crate::value::json_len(&e.args)).sum();
    let out_bytes = r.result.as_ref().map(crate::value::json_len).unwrap_or(0);
    let depth = r.events.iter().map(|e| e.stack.len()).max().unwrap_or(0);
    m.extend([
        ("fuel".to_string(), r.totals.fuel),
        ("peak_memory".into(), r.totals.peak_memory),
        ("output_bytes".into(), out_bytes as u64),
        ("host_arg_bytes".into(), arg_bytes as u64),
        ("virtual_ns".into(), r.totals.virtual_ns),
        ("cost".into(), r.totals.cost),
        ("call_depth".into(), depth as u64),
    ]);
    m
}

/// A new maximum must beat the old one by 5 % (and by at least 1).
fn beats(new: u64, old: u64) -> bool {
    new > old && new - old >= (old / 20).max(1)
}

/// What all workers share: the corpus and what it has covered.
struct State {
    corpus: Vec<Arc<Entry>>,
    /// Times each corpus entry was picked as a parent.
    picked: Vec<u32>,
    features: BTreeSet<String>,
    /// metric → (value, run id of the entry holding it).
    maxima: BTreeMap<String, (u64, String)>,
    stages: BTreeMap<Stage, StageStat>,
    known: BTreeSet<String>,
    new_findings: Vec<Finding>,
    observed: BTreeMap<String, Finding>,
    comparison_progress:BTreeMap<String,(u64,String)>,
    asserts: Vec<AssertStat>,
    faults: crate::faults::Search,
    /// Runs admitted, and runs handed to a worker.
    runs: u64,
    started: u64,
    kept: u64,
    last_new: u64,
    max_corpus: usize,
    stopped: Option<&'static str>,
    /// Call shapes whose runs had their pair checks.
    checked: BTreeSet<String>,
}

/// A run and what the worker derived from it.
struct Executed {
    feedback:crate::feedback::Feedback,
    /// None: no asserts, or skipped by sampling.
    asserts: Option<Vec<AssertObs>>,
    r: Arc<RunRecord>,
    findings: Vec<Finding>,
    features: BTreeSet<String>,
    metrics: Vec<(String, u64)>,
}

/// The unlocked half of an evaluation: run, detectors, features.
fn execute(app: &App, st: &Statics, spec: &RunSpec, prop: Option<&Property>, probe:&crate::feedback::Probe, judge: &Judge) -> Executed {
    let r = Arc::new(app.run(spec));
    if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
        return Executed { feedback:Default::default(), asserts: None, r, findings: vec![], features: BTreeSet::new(), metrics: vec![] };
    }
    let asserts = (!judge.list.is_empty() && r.outcome.kind == OutcomeKind::Ok && judge.sample()).then(|| judge.judge(&r, &app.manifest));
    let mut findings = per_run(&r, &app.manifest);
    findings.extend(prop.and_then(|p| p.finding(&r, &app.manifest)));
    let feedback=if r.outcome.kind==OutcomeKind::Ok {probe.collect(spec)}else{Default::default()};
    let mut features = features(&r, st, app);
    features.extend(feedback.features());
    let metrics = if r.outcome.kind == OutcomeKind::Ok { metrics(&r) } else { vec![] };
    Executed { feedback, asserts, r, findings, features, metrics }
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl State {
    /// Keeps a run if it is new in any way, and collects its findings.
    /// Returns the run, whether it was kept, and the findings new in it.
    fn admit(&mut self, spec: RunSpec, stage: Stage, ex: Executed) -> (Arc<RunRecord>, bool, Vec<Finding>) {
        let Executed { feedback, asserts, r, findings, features: feats, metrics } = ex;
        self.runs += 1;
        let assert_reasons = match asserts {
            Some(obs) => self.observe(&r, obs, stage),
            None if r.outcome.kind == OutcomeKind::Ok => {
                self.asserts.iter_mut().for_each(|a| a.sampled_out += 1);
                vec![]
            }
            None => vec![],
        };
        let stat = self.stages.entry(stage).or_default();
        stat.runs += 1;
        if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            stat.invalid += 1;
            return (r, false, vec![]);
        }
        let mut found: Vec<Finding> = Vec::new();
        for f in findings {
            let novel = self.known.insert(f.id.clone());
            if novel {
                self.new_findings.push(f.clone());
            }
            let refresh = self.observed.get(&f.id).is_none_or(|old| f.severity > old.severity);
            if refresh {
                self.observed.insert(f.id.clone(), f.clone());
                found.push(f);
            }
        }
        stat.findings += found.len() as u64;
        let mut reasons = Vec::new();
        if !found.is_empty() {
            reasons.push(format!("findings {}", found.len()));
        }
        reasons.extend(assert_reasons);
        if stage!=Stage::Check && let Some((group,distance))=feedback.progress()
            && (self.comparison_progress.contains_key(&group) || self.comparison_progress.len()<self.max_corpus.max(2)/2)
            && self.comparison_progress.get(&group).is_none_or(|(old,_)|distance<*old) {
            self.comparison_progress.insert(group,(distance,r.id.clone()));
            reasons.push(format!("comparison distance {distance}"));
        }
        let fresh = feats.iter().filter(|f| !self.features.contains(*f)).count();
        if fresh > 0 {
            reasons.push(format!("features {fresh}"));
            self.features.extend(feats);
        }
        for (m, v) in metrics {
            match self.maxima.get(&m) {
                Some((old, _)) if !beats(v, *old) => {}
                old => {
                    if old.is_some() {
                        reasons.push(format!("max {m} {v}"));
                    }
                    self.maxima.insert(m, (v, r.id.clone()));
                }
            }
        }
        // Check runs are artificial (pinned, slowed): never parents.
        let keep = (!reasons.is_empty() && stage != Stage::Check) || stage == Stage::Seed;
        if keep {
            stat.kept += 1;
            if stage != Stage::Seed {
                self.kept += 1;
                self.last_new = self.runs;
            }
            self.corpus.push(Arc::new(Entry { spec, run: r.id.clone(), stage, reasons, feedback, record: Some(r.clone()), links: OnceLock::new() }));
            self.picked.push(0);
            self.prune();
        }
        if !found.is_empty() {
            self.last_new = self.runs;
        }
        (r, keep, found)
    }

    /// Counts what each assert said. A break, or a run closer to breaking one
    /// than any before, is a reason to keep the run.
    fn observe(&mut self, r: &RunRecord, obs: Vec<AssertObs>, stage: Stage) -> Vec<String> {
        let mut reasons = Vec::new();
        for (a, o) in self.asserts.iter_mut().zip(obs) {
            a.evaluated += 1;
            match o.verdict {
                Verdict::Holds { vacuous } => {
                    a.holds += 1;
                    a.vacuous += u64::from(vacuous);
                }
                Verdict::Broken { conjunct, evidence } => {
                    a.broken += 1;
                    if a.broken_at.is_none() {
                        a.broken_at = Some(json!({"run": r.id, "at_run": self.runs, "failing": conjunct, "evidence": evidence}));
                        reasons.push(format!("assert {} broken", a.name));
                    }
                }
                Verdict::Rejected => a.rejected += 1,
                Verdict::Undefined { .. } => a.undefined += 1,
                Verdict::Error { conjunct, message } => {
                    a.errors += 1;
                    a.first_error.get_or_insert_with(|| format!("{conjunct}: {message}"));
                }
            }
            if let Some(m) = o.margin
                && stage != Stage::Check
                && a.best.as_ref().is_none_or(|(old, _)| m.margin < *old)
            {
                if a.best.is_some() {
                    a.closer += 1;
                    reasons.push(format!("assert {} margin {}", a.name, m.margin));
                }
                a.best = Some((m.margin, r.id.clone()));
                a.closest = Some(json!({"run": r.id, "at_run": self.runs, "margin": m.margin, "conjunct": m.conjunct, "left": m.left, "right": m.right}));
            }
        }
        reasons
    }

    /// Runs that hold an assert's closest approach or break.
    fn assert_holders(&self) -> impl Iterator<Item = &String> {
        self.asserts.iter().filter_map(|a| a.best.as_ref().map(|(_, r)| r))
    }

    /// Drops the oldest entry that holds no maximum once the corpus is full.
    fn prune(&mut self) {
        if self.corpus.len() <= self.max_corpus {
            return;
        }
        let holders: BTreeSet<&String> = self.maxima.values().chain(self.comparison_progress.values()).map(|(_, r)| r).chain(self.assert_holders()).collect();
        if let Some(i) = (1..self.corpus.len()).find(|&i| !holders.contains(&self.corpus[i].run)) {
            self.corpus.remove(i);
            self.picked.remove(i);
        }
    }

    /// Why to stop, if it is time.
    fn stop(&self, opts: &FuzzOpts, started: Instant) -> Option<&'static str> {
        if let Some(s) = self.stopped {
            return Some(s);
        }
        if opts.runs.is_some_and(|n| self.started >= n) {
            return Some("runs");
        }
        if opts.time.is_some_and(|t| started.elapsed() >= t) {
            return Some("time");
        }
        if let Some(k) = &opts.stop_on
            && self.new_findings.iter().any(|f| f.kind == *k)
        {
            return Some("check_failed");
        }
        if opts.until == Until::NewFinding && !self.new_findings.is_empty() {
            return Some("new_finding");
        }
        if opts.until == Until::Plateau && self.runs - self.last_new >= opts.plateau {
            return Some("plateau");
        }
        None
    }

    fn pick_parent(&mut self, rng: &mut StdRng) -> usize {
        let holders: Vec<usize> = {
            let h: BTreeSet<&String> = self.maxima.values().chain(self.comparison_progress.values()).map(|(_, r)| r).chain(self.assert_holders()).collect();
            (0..self.corpus.len()).filter(|i| h.contains(&self.corpus[*i].run)).collect()
        };
        // Run time in ms, bucketed by powers of two: a 4 s input should not
        // breed most of the campaign just because it holds a maximum.
        let slow = |i: usize| self.corpus[i].record.as_ref().map_or(0, |r| 64 - (r.totals.wall_us / 1000).leading_zeros());
        let i = if !holders.is_empty() && rng.random_bool(0.3) {
            // Two random holders; keep the faster one.
            let a = holders[rng.random_range(0..holders.len())];
            let b = holders[rng.random_range(0..holders.len())];
            if slow(a) <= slow(b) { a } else { b }
        } else {
            // Two random picks; keep the faster, then the less-picked one.
            let a = rng.random_range(0..self.corpus.len());
            let b = rng.random_range(0..self.corpus.len());
            let cost = |i: usize| (slow(i), self.picked[i]);
            if cost(a) <= cost(b) { a } else { b }
        };
        self.picked[i] += 1;
        i
    }

    fn pick_stage(&self, rng: &mut StdRng) -> Stage {
        let w: Vec<f64> = STAGES
            .iter()
            .map(|s| {
                let st = self.stages.get(s).cloned().unwrap_or_default();
                (1.0 + (st.kept + 3 * st.findings) as f64) / (5.0 + st.runs as f64) + 0.02
            })
            .collect();
        let total: f64 = w.iter().sum();
        let mut x = rng.random_range(0.0..total);
        for (s, w) in STAGES.iter().zip(w) {
            if x < w {
                return *s;
            }
            x -= w;
        }
        Stage::Request
    }
}

/// Makes inputs; one per worker, with its own random generator.
struct Mutator<'a> {
    app: &'a App,
    words: &'a [String],
    consts: &'a [i64],
    keys: &'a [String],
    /// Platform functions with their result type.
    funcs: &'a [(String, Type)],
    rng: StdRng,
}

impl Mutator<'_> {
    fn pick<'b, T>(&mut self, items: &'b [T]) -> Option<&'b T> {
        (!items.is_empty()).then(|| &items[self.rng.random_range(0..items.len())])
    }

    fn word(&mut self) -> String {
        let w = self.words;
        self.pick(w).cloned().unwrap_or_else(|| "x".into())
    }

    fn number(&mut self, old: Option<i64>) -> i64 {
        const EDGES: [i64; 22] =
            [0, 1, 2, 3, 7, 10, 31, 32, 63, 64, 100, 127, 128, 255, 256, 1000, 1024, 4096, 65535, 65536, 2_147_483_647, 4_294_967_295];
        let c = self.consts;
        match (self.rng.random_range(0..4u8), old) {
            (0, Some(n)) => *self.pick(&[n + 1, n - 1, n * 2, n * 10, n / 2]).expect("non-empty"),
            (1, _) if !c.is_empty() => {
                let k = *self.pick(c).expect("non-empty");
                *self.pick(&[k, k - 1, k + 1]).expect("non-empty")
            }
            (2, _) => self.rng.random_range(0..1000),
            _ => *self.pick(&EDGES).expect("non-empty"),
        }
    }

    fn text(&mut self) -> String {
        const ODD: [&str; 13] = ["", "Zoë", "東京", "👩‍💻", "<b>x</b>", "\"'<>&", "../..", "%00", "2028-02-29", "-1", "a b", "\u{202e}x", "a\r\nb"];
        match self.rng.random_range(0..7u8) {
            0 | 1 => self.word(),
            6 => crate::output::canary_for(&self.app.manifest, self.rng.random_range(0..1u64 << 32)),
            2 => {
                let n = *self.pick(&scale::LENGTH_SIZES).expect("non-empty");
                "a".repeat(n as usize)
            }
            3 => format!("{} {}", self.word(), self.word()),
            4 => self.number(None).to_string(),
            _ if self.app.manifest.has_sinks() && self.rng.random_bool(0.3) => {
                const ATTACKS: [&str; 5] = ["' OR '1'='1", "../../etc/passwd", "; ls", "$(id)", "http://169.254.169.254/"];
                self.pick(&ATTACKS).expect("non-empty").to_string()
            }
            _ if self.app.manifest.has_output_labels() && self.rng.random_bool(0.4) => {
                const ATTACKS: [&str; 6] =
                    ["//evil.example/", "https://evil.example/", "/\\evil.example", "javascript:alert(1)", "<img src=x onerror=alert(1)>", "\" onmouseover=\"alert(1)"];
                self.pick(&ATTACKS).expect("non-empty").to_string()
            }
            _ => self.pick(&ODD).expect("non-empty").to_string(),
        }
    }

    /// Mutates one node of the request.
    fn mutate_request(&mut self, args: &mut [Value]) -> bool {
        let mut ptrs = Vec::new();
        for (i, a) in args.iter().enumerate() {
            nodes(a, format!("/{i}"), &mut ptrs);
        }
        let Some(p) = self.pick(&ptrs).cloned() else { return false };
        let mut root = Value::Array(args.to_vec());
        let Some(node) = root.pointer_mut(&p) else { return false };
        let old = node.clone();
        let new = match &old {
            Value::Number(n) => {
                let v = self.number(n.as_i64());
                json!(if n.as_i64().is_some_and(|x| x >= 0) { v.max(0) } else { v })
            }
            Value::Bool(b) => json!(!b),
            Value::String(s) if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) => {
                json!(self.number(s.parse().ok()).max(0).to_string())
            }
            Value::String(_) => json!(self.text()),
            Value::Array(a) if is_pairs(a) => {
                let mut a = a.clone();
                match self.rng.random_range(0..5u8) {
                    0..=2 => {
                        let k = self.word();
                        let v = if self.rng.random_bool(0.5) { self.number(None).to_string() } else { self.text() };
                        a.push(json!([k, v]));
                    }
                    3 if !a.is_empty() => {
                        let i = self.rng.random_range(0..a.len());
                        a.remove(i);
                    }
                    _ if !a.is_empty() => {
                        let i = self.rng.random_range(0..a.len());
                        let x = a[i].clone();
                        a.push(x);
                    }
                    _ => return false,
                }
                Value::Array(a)
            }
            Value::Array(a) if !a.is_empty() => {
                let mut a = a.clone();
                let i = self.rng.random_range(0..a.len());
                match self.rng.random_range(0..3u8) {
                    0 => {
                        a.remove(i);
                    }
                    1 => {
                        let x = a[i].clone();
                        a.push(x);
                    }
                    _ => a = a.iter().chain(a.iter()).cloned().collect(),
                }
                Value::Array(a)
            }
            _ => return false,
        };
        *node = new;
        if let Value::Array(v) = root {
            args.clone_from_slice(&v);
        }
        true
    }

    fn gen_opts(&mut self, base: GenOpts) -> GenOpts {
        let mut o = base;
        let p = 0.4;
        if self.rng.random_bool(p) {
            o.list_len = Some(*self.pick(&[0usize, 1, 2, 3, 5, 8]).expect("non-empty"));
        }
        if self.rng.random_bool(p) {
            let w = self.word();
            let canary = if self.app.manifest.has_sinks() { "canary-sink" } else { "canary" };
            let modes = ["words", "empty", "long", "unicode", "html", "utf8-3", "utf8-3o", canary];
            o.strings = Some(if self.rng.random_bool(0.3) { format!("={w}") } else { self.pick(&modes).expect("non-empty").to_string() });
        }
        if self.rng.random_bool(p) {
            let c = self.consts;
            o.numbers = match self.pick(c) {
                Some(c) if self.rng.random_bool(0.5) => Some(format!("={c}")),
                _ => Some(self.pick(&["small", "edge"]).expect("non-empty").to_string()),
            };
        }
        if self.rng.random_bool(p) {
            o.options = Some(self.pick(&["some", "none", "mixed"]).expect("non-empty").to_string());
        }
        if self.rng.random_bool(p) {
            o.results = Some(self.pick(&["ok", "err", "mixed"]).expect("non-empty").to_string());
        }
        if self.rng.random_bool(p) {
            o.seed = Some(self.rng.random_range(0..1_000_000));
        }
        o
    }

    fn current_opts(plan: &Plan, key: &str) -> GenOpts {
        plan.0
            .get(key)
            .and_then(|p| p.response.generate.clone())
            .or_else(|| plan.0.get("_defaults").and_then(|p| p.response.generate.clone()))
            .unwrap_or_default()
    }

    fn set_generate(plan: &mut Plan, key: &str, opts: GenOpts) {
        let fp = plan.0.entry(key.to_string()).or_default();
        fp.response = Response { generate: Some(opts), latency_ms: fp.response.latency_ms, ..Default::default() };
    }

    /// Applies one stage to a copy of the parent (`other` is the second
    /// parent of a splice). None if it does not apply.
    fn mutate(&mut self, stage: Stage, parent: &Entry, other: Option<&Entry>) -> Option<RunSpec> {
        let mut spec = parent.spec.clone();
        let rec = parent.record.clone();
        match stage {
            Stage::Seed | Stage::Check | Stage::Fault => return None,
            Stage::Request if !self.keys.is_empty() && self.rng.random_bool(0.4) => {
                // A key the app is known to read, with a new value.
                let k = self.pick(self.keys)?.clone();
                let v = match self.rng.random_range(0..3u8) {
                    0 => self.number(None).to_string(),
                    1 => self.word(),
                    _ => self.text(),
                };
                let (i, path) = scale::split_arg(&k);
                scale::set_text(spec.args.get_mut(i)?, path, &v).ok()?;
            }
            Stage::Request => {
                let n = 1 + self.rng.random_range(0..2u8);
                let mut any = false;
                for _ in 0..n {
                    any |= self.mutate_request(&mut spec.args);
                }
                // Mostly requests the platform lets through.
                if self.rng.random_bool(0.85) {
                    crate::constraints::conform_request(&mut spec.args, &self.app.manifest, self.rng.random());
                }
                any.then_some(())?;
            }
            Stage::Compare => {
                let candidates=crate::feedback::substitutions(&spec.args,&parent.feedback.comparisons);
                let changed=self.pick(&candidates).is_some_and(|patch|patch.apply(&mut spec.args));
                if !changed && !self.mutate_request(&mut spec.args){return None;}
                crate::constraints::conform_request(&mut spec.args,&self.app.manifest,self.rng.random());
            }
            Stage::Structured => {
                // Request strings and observed host-result strings use the same
                // parser. Model-backed successes remain owned by their datasets.
                let mut root = Value::Array(spec.args.clone());
                let request_paths = crate::structured::locations(&root);
                let host_values: Vec<_> = rec.as_ref().into_iter().flat_map(|r| r.events.iter()).take(256)
                    .filter(|e| !self.app.manifest.function(&e.func).is_some_and(|f| f.query.is_some() || f.mutation.is_some()))
                    .filter_map(|e| {
                        let value = e.result.as_ref()?;
                        let paths = crate::structured::locations(value);
                        (!paths.is_empty()).then_some((e, paths))
                    }).collect();
                if !request_paths.is_empty() && (host_values.is_empty() || self.rng.random_bool(0.5)) {
                    let path = self.pick(&request_paths)?;
                    let slot = root.pointer_mut(path)?;
                    *slot = json!(crate::structured::mutate(slot.as_str()?, &mut self.rng, self.words, self.consts)?);
                    spec.args = root.as_array()?.clone();
                    crate::constraints::conform_request(&mut spec.args, &self.app.manifest, spec.seed);
                } else {
                    let (event, paths) = self.pick(&host_values)?;
                    let path = self.pick(paths)?;
                    let mut value = event.result.clone()?;
                    let slot = value.pointer_mut(path)?;
                    *slot = json!(crate::structured::mutate(slot.as_str()?, &mut self.rng, self.words, self.consts)?);
                    spec.plan.0.entry(event.func.clone()).or_default().on_call.insert(event.call.to_string(), Response { ret: Some(value), ..Default::default() });
                }
            }
            Stage::HostValues => {
                let (key, _) = self.pick(self.funcs)?.clone();
                if self.app.manifest.function(&key).is_some_and(|f| f.query.is_some()) {
                    spec.plan.0.entry("_defaults".into()).or_default().dataset_seed = Some(self.rng.random());
                    return Some(spec);
                }
                let o = self.gen_opts(Self::current_opts(&spec.plan, &key));
                Self::set_generate(&mut spec.plan, &key, o);
            }
            Stage::GrowList => {
                let fs: Vec<_> = self.funcs.iter().filter(|(_, t)| has_list(t)).cloned().collect();
                let (key, _) = self.pick(&fs)?.clone();
                if let Some(q) = self.app.manifest.function(&key).and_then(|f| f.query.as_ref()) {
                    let n = *self.pick(&[0usize, 1, 2, 4, 8, 16, 32])?;
                    spec.plan.0.entry("_defaults".into()).or_default().dataset_rows.insert(q.dataset.clone(), n);
                    return Some(spec);
                }
                let mut o = Self::current_opts(&spec.plan, &key);
                // Bigger lists are `amplify`'s job; here they would only slow runs.
                o.list_len = Some(*self.pick(&[4usize, 8, 16, 32]).expect("non-empty"));
                Self::set_generate(&mut spec.plan, &key, o);
            }
            Stage::GrowInput => {
                let (knobs, _) = request_knobs(&spec.args);
                let k = self.pick(&knobs)?.clone();
                let sizes = scale::default_sizes(&k);
                let n = *self.pick(&sizes[sizes.len() / 2..])?;
                spec = scale::apply(self.app, &spec, &k, n).ok()?;
            }
            Stage::Permute => {
                let r = rec?;
                let with_list: Vec<_> = r.events.iter().filter(|e| e.result.as_ref().is_some_and(|v| first_list(v).is_some_and(|a| !a.is_empty()))).cloned().collect();
                let e = self.pick(&with_list)?.clone();
                if self.app.manifest.function(&e.func).is_some_and(|f| f.query.is_some()) { return None; }
                let mut v = e.result.clone()?;
                let a = first_list_mut(&mut v)?;
                match self.rng.random_range(0..4u8) {
                    0 => {
                        let i = self.rng.random_range(0..a.len());
                        let x = a[i].clone();
                        a.insert(i, x);
                    }
                    1 => a.reverse(),
                    // Doubling compounds over generations: cap it.
                    2 if a.len() <= MAX_PERMUTED / 2 => {
                        let c = a.clone();
                        a.extend(c);
                    }
                    _ => {
                        let i = self.rng.random_range(0..a.len());
                        a.remove(i);
                    }
                }
                a.truncate(MAX_PERMUTED);
                spec.plan.0.entry(e.func.clone()).or_default().on_call.insert(e.call.to_string(), Response { ret: Some(v), ..Default::default() });
            }
            Stage::Env => {
                if self.rng.random_bool(0.5) {
                    let (t, _) = *self.pick(EDGE_TIMES)?;
                    spec.now = t.to_string();
                } else {
                    let y = self.rng.random_range(2020..2040);
                    let m = self.rng.random_range(1..=12);
                    let d = self.rng.random_range(1..=28);
                    let h = self.rng.random_range(0..24);
                    let mi = self.rng.random_range(0..60);
                    spec.now = format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:00");
                }
                if self.rng.random_bool(0.5) {
                    spec.seed = self.rng.random_range(0..1_000_000);
                }
                let entry = self.app.manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &spec.export));
                if let (Some(e), Some(a)) = (entry, spec.args.first_mut()) {
                    set_clock_fields(a, &e.fields, &spec.now);
                }
            }
            Stage::Splice => {
                let other = other?;
                if self.rng.random_bool(0.5) {
                    spec.plan = other.spec.plan.clone();
                } else {
                    spec.args = other.spec.args.clone();
                }
            }
            Stage::Crawl => {
                let r = rec?;
                let (refs, inputs) = parent.links.get_or_init(|| {
                    let refs = urls::extract_output(&r, &self.app.manifest).into_iter().filter(|u| u.kind == "same_host").collect();
                    (refs, r.result.as_ref().map(form_inputs).unwrap_or_default())
                });
                let u = self.pick(refs)?.clone();
                let words: Vec<String> = (0..inputs.len()).map(|_| if self.rng.random_bool(0.5) { self.number(None).to_string() } else { self.word() }).collect();
                let req = spec.args.first_mut()?;
                if !crawl_into(req, &self.app.manifest.entry.as_ref()?.fields, &u.url, &u.method, inputs, &words) {
                    return None;
                }
            }
        }
        Some(spec)
    }
}

/// JSON pointers of every node worth mutating.
pub(crate) fn nodes(v: &Value, ptr: String, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                nodes(x, format!("{ptr}/{}", k.replace('~', "~0").replace('/', "~1")), out);
            }
        }
        Value::Array(a) => {
            out.push(ptr.clone());
            if is_pairs(a) {
                for (i, _) in a.iter().enumerate() {
                    out.push(format!("{ptr}/{i}/1"));
                }
            } else {
                for (i, x) in a.iter().enumerate() {
                    nodes(x, format!("{ptr}/{i}"), out);
                }
            }
        }
        _ => out.push(ptr),
    }
}

/// `[["k","v"], …]` (an empty list counts: query and form start empty).
fn is_pairs(a: &[Value]) -> bool {
    a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string()))
}

fn has_list(t: &Type) -> bool {
    match t {
        Type::List(_) => true,
        Type::Option(o) => has_list(&o.ty()),
        Type::Result(r) => r.ok().is_some_and(|t| has_list(&t)),
        _ => false,
    }
}

pub(crate) fn first_list(v: &Value) -> Option<&Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 => o.values().next().and_then(first_list),
        _ => None,
    }
}

pub(crate) fn first_list_mut(v: &mut Value) -> Option<&mut Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 => o.values_mut().next().and_then(first_list_mut),
        _ => None,
    }
}

/// Names of form inputs in a result's strings.
pub(crate) fn form_inputs(v: &Value) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => {
                for c in INPUT_NAME.captures_iter(s) {
                    if let Some(m) = c.get(1).or(c.get(2)).or(c.get(3)) {
                        out.insert(m.as_str().to_string());
                    }
                }
            }
            Value::Array(a) => stack.extend(a),
            Value::Object(o) => stack.extend(o.values()),
            _ => {}
        }
    }
    out.into_iter().take(20).collect()
}

/// Request fields by role: `http.path`, `http.query`, `http.method`,
/// `http.form`; without roles, fields named `path`, `query`, `method`, `form`.
pub(crate) fn role_path(fields: &BTreeMap<String, String>, req: &Value, role: &str) -> Option<String> {
    fields
        .iter()
        .find(|(_, r)| r.as_str() == format!("http.{role}"))
        .map(|(p, _)| p.clone())
        .or_else(|| field(req, role).is_some().then(|| role.to_string()))
}

/// The functions a run calls, in order, repeats collapsed.
fn call_shape(r: &RunRecord) -> String {
    let mut out: Vec<&str> = Vec::new();
    for e in &r.events {
        if out.last() != Some(&e.func.as_str()) {
            out.push(&e.func);
        }
    }
    format!("{}\0{}", r.spec.export, out.join("\0"))
}

/// Seeds that trace data flow: every free string of the request (and a
/// pair for each key the app reads) set to a canary; and every host
/// function returning canary strings.
fn flow_seeds(app: &App, base: &RunSpec, keys: &[String], funcs: &[(String, Type)]) -> Vec<RunSpec> {
    let mut out = Vec::new();
    let entry = app.manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &base.export));
    let fixed: Vec<&String> = entry
        .map(|e| e.fields.iter().filter(|(_, r)| r.starts_with("clock.") || r.as_str() == "http.path" || r.as_str() == "http.method").map(|(p, _)| p).collect())
        .unwrap_or_default();
    let mut req = base.clone();
    let mut n = 0u64;
    if let Some(a) = req.args.first_mut() {
        let mut ptrs = Vec::new();
        nodes(a, String::new(), &mut ptrs);
        let skip = |p: &str| {
            let dotted = p.trim_start_matches('/').replace('/', ".");
            fixed.iter().any(|f| dotted == **f || dotted.starts_with(&format!("{f}.")))
                || ["path", "method"].contains(&dotted.as_str())
        };
        for p in ptrs {
            if skip(&p) {
                continue;
            }
            if let Some(v) = a.pointer_mut(&p)
                && v.is_string()
            {
                n += 1;
                *v = json!(crate::output::canary_for(&app.manifest, n));
            }
        }
        if let Some(q) = role_path(&entry.map(|e| e.fields.clone()).unwrap_or_default(), a, "query")
            && let Some(Value::Array(pairs)) = crate::harness::field_mut(a, &q)
        {
            for k in keys {
                if !pairs.iter().any(|p| p[0].as_str() == Some(k)) {
                    n += 1;
                    pairs.push(json!([k, crate::output::canary_for(&app.manifest, n)]));
                }
            }
        }
    }
    if n > 0 {
        out.push(req);
    }
    let strings: Vec<&String> = funcs.iter().filter(|(_, t)| has_string(t)).map(|(k, _)| k).collect();
    let canary = if app.manifest.has_sinks() { "canary-sink" } else { "canary" };
    if !strings.is_empty() {
        let mut s = base.clone();
        for k in strings {
            let o = Mutator::current_opts(&s.plan, k);
            Mutator::set_generate(&mut s.plan, k, GenOpts { strings: Some(canary.into()), results: Some("ok".into()), options: Some("some".into()), list_len: Some(2), ..o });
        }
        out.push(s);
    }
    out
}

pub(crate) fn has_string(t: &Type) -> bool {
    match t {
        Type::String => true,
        Type::List(l) => has_string(&l.ty()),
        Type::Option(o) => has_string(&o.ty()),
        Type::Result(r) => r.ok().is_some_and(|t| has_string(&t)),
        Type::Record(r) => r.fields().any(|f| has_string(&f.ty)),
        Type::Tuple(t) => t.types().any(|t| has_string(&t)),
        _ => false,
    }
}

/// Points the request at a URL the app linked to (and fills its form).
pub(crate) fn crawl_into(req: &mut Value, fields: &BTreeMap<String, String>, url: &str, method: &str, inputs: &[String], values: &[String]) -> bool {
    let full = if url.starts_with('/') { format!("http://app.invalid{url}") } else { url.to_string() };
    let Ok(u) = url::Url::parse(&full) else { return false };
    let mut changed = false;
    if let Some(p) = role_path(fields, req, "path")
        && let Some(slot) = crate::harness::field_mut(req, &p)
        && slot.is_string()
    {
        *slot = json!(u.path());
        changed = true;
    }
    if let Some(p) = role_path(fields, req, "query")
        && let Some(slot) = crate::harness::field_mut(req, &p)
        && slot.is_array()
    {
        *slot = Value::Array(u.query_pairs().map(|(k, v)| json!([k, v])).collect());
        changed = true;
    }
    if let Some(p) = role_path(fields, req, "method")
        && let Some(slot) = crate::harness::field_mut(req, &p)
        && slot.is_string()
    {
        *slot = json!(method);
        changed = true;
    }
    if method != "GET"
        && let Some(p) = role_path(fields, req, "form")
        && let Some(slot) = crate::harness::field_mut(req, &p)
        && slot.is_array()
    {
        *slot = Value::Array(inputs.iter().zip(values).map(|(k, v)| json!([k, v])).collect());
        changed = true;
    }
    changed
}

/// Sees every run with whether it was kept and the findings new in it.
pub type OnRun<'a> = &'a (dyn Fn(&RunRecord, bool, &[Finding]) + Sync);

/// Runs a campaign. `on_run(record, kept, new_findings)` sees every run so
/// the caller can store kept runs and finding runs.
pub fn fuzz(
    app: &App,
    base: &RunSpec,
    prior: Vec<Entry>,
    known_findings: BTreeSet<String>,
    opts: &FuzzOpts,
    on_run: OnRun,
) -> anyhow::Result<(FuzzReport, Corpus)> {
    if opts.runs == Some(0) { anyhow::bail!("run budget must be positive"); }
    let started = Instant::now();
    let probe=crate::feedback::Probe::new(app,opts.internal_feedback);
    let st = Statics::parse(&app.bytes)?;
    let words = dictionary(&st, opts.dict_limit);
    let mut consts = compare_constants(&st, 32);
    // Numbers in an assert are its boundaries: `days <= 31` makes 30, 31, 32 worth trying.
    for (_, a) in &opts.asserts {
        consts.extend(a.constants().into_iter().filter(|c| !consts.contains(c)).collect::<Vec<_>>());
    }
    let judge = Judge { list: &opts.asserts, eval_ns: AtomicU64::new(0), n: AtomicU64::new(0), started, jobs: par::jobs() as u64 };
    let funcs: Vec<(String, Type)> = app
        .imports
        .iter()
        .filter(|i| i.kind == ImportKind::Platform)
        .flat_map(|i| i.funcs.iter())
        .filter(|f| app.manifest.function(&f.key).and_then(|s| s.fails) != Some(false))
        .filter_map(|f| f.ty.results().next().map(|t| (f.key.clone(), t)))
        .collect();
    let fuel = app.manifest.limits.fuel.saturating_mul(2);
    let state = Mutex::new(State {
        corpus: Vec::new(),
        picked: Vec::new(),
        features: BTreeSet::new(),
        maxima: BTreeMap::new(),
        stages: BTreeMap::new(),
        known: known_findings,
        new_findings: Vec::new(),
        observed: BTreeMap::new(),
        comparison_progress:BTreeMap::new(),
        asserts: opts.asserts.iter().map(|(n, a)| AssertStat { name: n.clone(), property: a.expr.text.clone(), ..Default::default() }).collect(),
        faults: crate::faults::Search::new(),
        runs: 0,
        started: 0,
        kept: 0,
        last_new: 0,
        max_corpus: opts.max_corpus,
        stopped: None,
        checked: BTreeSet::new(),
    });
    let jobs = par::jobs();
    // Seeds: the example request as is, on the happy path, and earlier entries.
    let steady_base = RunSpec { plan: steady(&base.plan), fuel: base.fuel.min(fuel), ..base.clone() };
    let mut seeds = vec![base.clone(), steady_base.clone()];
    let discovery_runs = std::sync::atomic::AtomicU64::new(0);
    let mut modes = Vec::new();
    let mut keys = Vec::new();
    if opts.discover {
        let counted = |s: &RunSpec| {
            discovery_runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            app.run(s)
        };
        let d = scale::discover(app, &steady_base, opts.dict_limit, &counted)?;
        keys = d.keys;
        for c in d.contexts {
            modes.push(c.label);
            seeds.push(c.spec);
        }
    }
    // Request fields an assert reads are mutated more often.
    for (_, a) in &opts.asserts {
        for k in a.request_fields() {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    seeds.extend(flow_seeds(app, &steady_base, &keys, &funcs));
    seeds.extend(prior.into_iter().filter(|e| e.spec.component == app.hash && e.spec.contract == app.contract && e.spec.export == base.export).map(|e| e.spec));
    // Seeds run at once and are admitted in order.
    for s in &mut seeds {
        s.fuel = s.fuel.min(fuel);
    }
    if let Some(n) = opts.runs { seeds.truncate(n.min(usize::MAX as u64) as usize); }
    lock(&state).started += seeds.len() as u64;
    // Pair checks of a kept run, once per call shape.
    let check = |r: &RunRecord| {
        if r.outcome.kind != OutcomeKind::Ok {
            return;
        }
        let vs = metamorphic::variants(app, r);
        // Longer lists show more (a hash map's order, a duplicate).
        let longest = r.events.iter().filter_map(|e| e.result.as_ref().and_then(crate::detect::list_in)).map(Vec::len).max().unwrap_or(0);
        let key = format!("{}\0{:?}\0{}", call_shape(r), vs.iter().map(|v| (v.change, &v.func)).collect::<Vec<_>>(), usize::BITS - longest.min(8).leading_zeros());
        if !lock(&state).checked.insert(key) {
            return;
        }
        for v in vs {
            {
                let mut s = lock(&state);
                if s.stop(opts, started).is_some() {
                    return;
                }
                s.started += 1;
            }
            let mut ex = execute(app, &st, &v.spec, opts.property.as_ref(), &probe, &judge);
            ex.findings.retain(|f| !metamorphic::expected(&v, f));
            ex.findings.extend(metamorphic::compare(app, r, &v, &ex.r));
            let (vr, keep, found) = lock(&state).admit(v.spec, Stage::Check, ex);
            on_run(&vr, keep, &found);
        }
    };
    let done = par::map(&seeds, |s| execute(app, &st, s, opts.property.as_ref(), &probe, &judge));
    let mut kept_seeds = Vec::new();
    for (spec, ex) in seeds.into_iter().zip(done) {
        let (r, keep, found) = lock(&state).admit(spec, Stage::Seed, ex);
        lock(&state).faults.enqueue(app, r.clone());
        on_run(&r, keep, &found);
        kept_seeds.push(r);
    }
    par::map(&kept_seeds, |r| check(r));
    if lock(&state).corpus.is_empty() {
        anyhow::bail!("the seed request does not run; check it with `appfuzz run`");
    }
    let worker = |i: usize| {
        let mut m = Mutator { app, words: &words, consts: &consts, keys: &keys, funcs: &funcs, rng: StdRng::seed_from_u64(opts.seed.wrapping_add((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))) };
        loop {
            let (stage, parent, other, fault) = {
                let mut s = lock(&state);
                if let Some(why) = s.stop(opts, started) {
                    s.stopped = Some(why);
                    return;
                }
                s.started += 1;
                let stage = s.pick_stage(&mut m.rng);
                let p = s.pick_parent(&mut m.rng);
                let o = m.rng.random_range(0..s.corpus.len());
                let fault = if stage == Stage::Fault { s.faults.next(app) } else { None };
                (stage, s.corpus[p].clone(), (o != p).then(|| s.corpus[o].clone()), fault)
            };
            let candidate = match &fault {
                Some((base, recipe)) => recipe.variant(app, base).map(|v| v.spec),
                None => m.mutate(stage, &parent, other.as_deref()),
            };
            let Some(mut spec) = candidate else {
                let mut s = lock(&state);
                s.started -= 1;
                s.stages.entry(stage).or_default();
                continue;
            };
            // Sometimes stack a second, request-side change (havoc).
            if !matches!(stage, Stage::Structured | Stage::Fault) && m.rng.random_bool(0.2) {
                m.mutate_request(&mut spec.args);
            }
            spec.fuel = spec.fuel.min(fuel);
            let mut ex = execute(app, &st, &spec, opts.property.as_ref(), &probe, &judge);
            let sampled_out = ex.asserts.is_none() && !judge.list.is_empty() && ex.r.outcome.kind == OutcomeKind::Ok;
            if let Some((base, recipe)) = &fault {
                lock(&state).faults.observe(crate::faults::injected(base, recipe, &ex.r));
                let variant = metamorphic::Variant { change: metamorphic::Change::Fault, func: Some(recipe.func.clone()), call: Some(recipe.call), spec: spec.clone() };
                ex.findings.extend(crate::faults::compare(app, base, recipe, &variant, &ex.r));
            }
            let (r, keep, found) = lock(&state).admit(spec, stage, ex);
            // A sampled-out run that showed something new is judged anyway.
            if keep && sampled_out {
                let obs = judge.judge(&r, &app.manifest);
                let mut s = lock(&state);
                s.asserts.iter_mut().for_each(|a| a.sampled_out -= 1);
                s.observe(&r, obs, stage);
            }
            if keep && stage != Stage::Fault { lock(&state).faults.enqueue(app, r.clone()); }
            on_run(&r, keep, &found);
            if keep {
                check(&r);
            }
        }
    };
    std::thread::scope(|sc| {
        for i in 0..jobs {
            let w = &worker;
            sc.spawn(move || w(i));
        }
    });
    let fz = state.into_inner().unwrap_or_else(|e| e.into_inner());
    let mut maxima: Vec<Maximum> = fz.maxima.iter().map(|(m, (v, r))| Maximum { metric: m.clone(), value: *v, run: r.clone() }).collect();
    maxima.sort_by(|a, b| a.metric.cmp(&b.metric));
    let report = FuzzReport {
        runs: fz.runs,
        discovery_runs: discovery_runs.into_inner(),
        keys,
        modes,
        elapsed_ms: started.elapsed().as_millis() as u64,
        stopped: fz.stopped.unwrap_or("time").into(),
        corpus: fz.corpus.len(),
        kept: fz.kept,
        features: fz.features.len(),
        stages: fz.stages,
        maxima,
        findings: fz.observed.into_values().collect(),
        last_new_at_run: fz.last_new,
        jobs,
        feedback:probe.finish(),
        faults: fz.faults.coverage(),
        asserts: fz.asserts,
        assert_cost_pct: (!opts.asserts.is_empty()).then(|| {
            let (e, w) = (judge.eval_ns.load(AtomicOrdering::Relaxed) as f64, judge.budget_ns() as f64);
            (e * 1000.0 / w).round() / 10.0
        }),
    };
    let entries = fz.corpus.into_iter().map(Arc::unwrap_or_clone).collect();
    Ok((report, Corpus { component: app.state_key.clone(), entries }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_and_buckets() {
        assert_eq!(shape(&json!({"ok": []}), 2), "ok([])");
        assert_eq!(shape(&json!({"err": "x"}), 2), "err(s)");
        assert_eq!(bucket(5), 4);
        assert_eq!(bucket(200), 128);
        assert!(beats(106, 100) && !beats(104, 100) && beats(1, 0));
    }

    #[test]
    fn crawls_into_request() {
        let mut req = json!({"method": "GET", "path": "/", "query": [], "form": []});
        let ok = crawl_into(&mut req, &BTreeMap::new(), "/book?day=2026-01-02&x=1", "POST", &["copies".into()], &["3".into()]);
        assert!(ok);
        assert_eq!(req["path"], "/book");
        assert_eq!(req["query"], json!([["day", "2026-01-02"], ["x", "1"]]));
        assert_eq!(req["method"], "POST");
        assert_eq!(req["form"], json!([["copies", "3"]]));
    }

    #[test]
    fn finds_form_inputs() {
        let v = json!({"body": "<form><input name=\"copies\"><select name='room'></select></form>"});
        assert_eq!(form_inputs(&v), vec!["copies".to_string(), "room".to_string()]);
    }
}
