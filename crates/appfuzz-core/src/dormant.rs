//! Dormant code: host calls in the binary that no run reached, guarded by
//! something that looks like a trigger.
//!
//! A time bomb or a hidden flag waits for an input the review is unlikely to
//! send: a date, a magic value, or a hash of either (so the value is not in
//! the binary). The fuzzer cannot prove such code is dead, and most
//! unreached calls are ordinary error paths. `dormant_code` points a person
//! at the ones whose surroundings compare with large, odd constants, use the
//! constants of a hash function, or compare with times.
//!
//! Sites are call instructions, not functions: a dormant call is often
//! inlined into a function that runs on every request.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::record::RunRecord;
use crate::statics::{ModuleInfo, Statics};

/// A wrapper this small, around one host function, is looked through: its
/// callers are the sites.
pub const WRAPPER_MAX: u32 = 64;

static DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(19|20)\d\d-[01]\d(-[0-3]\d)?([ T][0-2]\d:[0-5]\d)?").unwrap());

/// A host call site: a call instruction in `func` at `at` (module offset).
#[derive(Debug, Clone)]
pub struct Site {
    pub module: String,
    pub func: u32,
    pub at: u64,
    pub host: String,
    /// Wrappers between the site and the import, innermost last.
    pub via: Vec<u32>,
}

fn is_wrapper(m: &ModuleInfo, reach: &BTreeMap<u32, BTreeSet<String>>, f: u32) -> bool {
    m.func(f).is_some_and(|fi| fi.instructions <= WRAPPER_MAX && fi.loops.is_empty()) && reach.get(&f).is_some_and(|s| s.len() == 1)
}

/// Every host call site of the component, through small wrappers.
pub fn sites(st: &Statics) -> Vec<Site> {
    let mut out = Vec::new();
    for m in &st.modules {
        let callers = m.callers();
        let reach = m.host_reach();
        for imp in &m.imports {
            let (Some(fi), Some(h)) = (imp.func, &imp.host) else { continue };
            // (callee, wrappers so far)
            let mut todo = vec![(fi, Vec::new())];
            let mut seen = BTreeSet::from([fi]);
            while let Some((callee, via)) = todo.pop() {
                for (c, off) in callers.get(&callee).into_iter().flatten() {
                    if via.len() < 3 && is_wrapper(m, &reach, *c) && seen.insert(*c) {
                        let mut v = via.clone();
                        v.insert(0, *c);
                        todo.push((*c, v));
                        continue;
                    }
                    out.push(Site { module: m.id.clone(), func: *c, at: *off, host: h.clone(), via: via.clone() });
                }
            }
        }
    }
    out
}

/// (module, offset) of every guest frame of every host call in the runs.
pub fn reached(runs: &[RunRecord]) -> BTreeSet<(String, u64)> {
    let mut out = BTreeSet::new();
    for r in runs {
        for e in &r.events {
            for f in &e.stack {
                if let Some(o) = f.offset {
                    out.insert((f.module.clone(), o as u64));
                }
            }
        }
    }
    out
}

/// Whether some run reached the site. Runs without offsets fall back to the
/// function.
pub fn is_reached(s: &Site, reached: &BTreeSet<(String, u64)>, funcs: &BTreeSet<(String, u32)>) -> bool {
    reached.contains(&(s.module.clone(), s.at)) || funcs.contains(&(s.module.clone(), s.func)) && !reached.iter().any(|(m, _)| *m == s.module)
}

/// A byte pattern such as `0x80808080` or `0x00ff00ff` (bit tricks on
/// words).
fn byte_pattern(u: u64, width: u32) -> bool {
    let b = u.to_le_bytes();
    let w = width as usize / 8;
    (0..w).all(|i| b[i] == b[i % 2]) || (0..w).all(|i| b[i] == b[i % 4]) && w == 8
}

/// About `2^k / d` for a small `d`: how compilers divide by a constant.
fn division_magic(u: u64) -> bool {
    (24..=66).any(|k| {
        let q = 2f64.powi(k) / u as f64;
        (2.0..=1024.0).contains(&q) && (q - q.round()).abs() < 1e-6 * q
    })
}

/// A 32-bit or wider constant nobody writes by hand for a limit or a flag.
fn odd_large(n: i64) -> bool {
    let w32 = n.unsigned_abs() < 1 << 32;
    let bits = if w32 { n as u32 as u64 } else { n as u64 };
    if byte_pattern(bits, if w32 { 32 } else { 64 }) || division_magic(bits) || division_magic(n.unsigned_abs()) {
        return false;
    }
    let u = n.unsigned_abs();
    if u >= 1 << 32 {
        return !(u.trailing_zeros() >= 24 || (u + 1).is_power_of_two() || u == i64::MAX as u64);
    }
    let w = n as u32;
    u >= 1 << 24 && w.trailing_zeros() < 16 && !(w as u64 + 1).is_power_of_two() && !(w.wrapping_neg() as u64).is_power_of_two() && !is_time(n)
}

/// Unix time in seconds or milliseconds, 2017 to 2049.
fn is_time(n: i64) -> bool {
    (1_500_000_000..2_500_000_000).contains(&n) || (1_500_000_000_000..2_500_000_000_000).contains(&n)
}

#[derive(Default)]
struct Signals {
    hashes: BTreeSet<&'static str>,
    large: BTreeSet<i64>,
    times: BTreeSet<String>,
}

fn signals(m: &ModuleInfo, f: u32, callers: &BTreeMap<u32, Vec<(u32, u64)>>) -> Signals {
    let mut g: BTreeSet<u32> = BTreeSet::from([f]);
    g.extend(callers.get(&f).into_iter().flatten().map(|(c, _)| *c));
    if let Some(fi) = m.func(f) {
        g.extend(fi.calls.iter().map(|(c, _)| *c).filter(|c| m.func(*c).is_some()));
    }
    let mut s = Signals::default();
    for fi in g.iter().filter_map(|x| m.func(*x)) {
        s.hashes.extend(fi.magic.iter().copied());
        for n in &fi.cmp_consts {
            if is_time(*n) {
                s.times.insert(n.to_string());
            } else if odd_large(*n) {
                s.large.insert(*n);
            }
        }
        for (_, t) in &fi.text_consts {
            if DATE.is_match(t) {
                s.times.insert(t.chars().take(19).collect());
            }
        }
    }
    s
}

/// `dormant_code` findings: unreached host call sites with a trigger nearby.
pub fn find(st: &Statics, runs: &[RunRecord]) -> Vec<Finding> {
    if runs.is_empty() {
        return Vec::new();
    }
    let hit = reached(runs);
    let funcs: BTreeSet<(String, u32)> = runs.iter().flat_map(|r| r.events.iter().flat_map(|e| e.stack.iter().map(|f| (f.module.clone(), f.func)))).collect();
    let mut by_func: BTreeMap<(String, u32), Vec<Site>> = BTreeMap::new();
    for s in sites(st) {
        if !is_reached(&s, &hit, &funcs) {
            by_func.entry((s.module.clone(), s.func)).or_default().push(s);
        }
    }
    let mut out = Vec::new();
    for ((mid, f), ss) in by_func {
        let Some(m) = st.module(&mid) else { continue };
        let callers = m.callers();
        let sig = signals(m, f, &callers);
        let large = !sig.large.is_empty();
        let hash = !sig.hashes.is_empty();
        let time = !sig.times.is_empty();
        let sev = match (large, hash, time) {
            (_, _, true) | (true, true, _) => Severity::Warn,
            (true, _, _) | (_, true, _) => Severity::Info,
            _ => continue,
        };
        let mut why = Vec::new();
        if large {
            why.push(format!(
                "compares with {}",
                sig.large
                    .iter()
                    .take(3)
                    .map(|n| format!("{:#x}", *n as u64 & if n.unsigned_abs() < 1 << 32 { 0xffff_ffff } else { u64::MAX }))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if hash {
            why.push(format!("uses {} constants", sig.hashes.iter().copied().collect::<Vec<_>>().join(", ")));
        }
        if time {
            why.push(format!("compares with times ({})", sig.times.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        }
        let hosts: BTreeSet<&str> = ss.iter().map(|s| s.host.as_str()).collect();
        let hosts: Vec<&str> = hosts.into_iter().collect();
        let name = m.label(f);
        let fully = !funcs.contains(&(mid.clone(), f));
        out.push(Finding::new(
            "dormant_code",
            &format!("{mid}\0{f}"),
            sev,
            format!(
                "{name} calls {} from code no run reached{}; nearby code {}",
                hosts.join(", "),
                if fully { "" } else { " (the function itself runs)" },
                why.join(" and ")
            ),
            json!({
                "module": mid, "func": f, "name": name,
                "sites": ss.iter().map(|s| json!({"host": s.host, "at": format!("{:x}", s.at), "via": s.via.iter().map(|v| m.label(*v)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                "function_runs": !fully,
                "signals": {
                    "large_constants": sig.large.iter().take(8).collect::<Vec<_>>(),
                    "hash_constants": sig.hashes.iter().collect::<Vec<_>>(),
                    "times": sig.times.iter().take(8).collect::<Vec<_>>(),
                },
                "needs_human": true,
                "look": format!("appfuzz wasm disasm {mid}:{f}"),
            }),
            None,
        ));
    }
    out
}

/// JSON for `unexplored`: unreached sites with the constants nearby.
pub fn site_json(m: &ModuleInfo, s: &Site) -> Value {
    json!({"host": s.host, "module": s.module, "func": s.func, "name": m.label(s.func), "at": format!("{:x}", s.at), "via": s.via.iter().map(|v| m.label(*v)).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odd_or_not() {
        assert!(odd_large(0x3759df13));
        assert!(odd_large(0x1234_5678_9abc_def1));
        assert!(odd_large(-0x2152_4111)); // 0xdeadbeef as i32
        assert!(!odd_large(0xffff_ffff));
        assert!(!odd_large(0x1_0000_0000));
        assert!(!odd_large(1 << 30));
        assert!(!odd_large(1000));
        assert!(!odd_large(-1));
        assert!(!odd_large(0x80808080u32 as i32 as i64));
        assert!(!odd_large(0x5555556));
        assert!(!odd_large(0x0101_0101_0101_0101));
        assert!(!odd_large(0xcccccccdu32 as i32 as i64));
        assert!(odd_large(0xd0e9e127a11608c7u64 as i64));
        assert!(!odd_large(1_800_000_000));
        assert!(is_time(1_800_000_000));
        assert!(DATE.is_match("2027-06-15 03:17"));
        assert!(!DATE.is_match("v2027"));
    }
}
