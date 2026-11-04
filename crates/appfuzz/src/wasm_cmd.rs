//! `appfuzz wasm …`: static views of the component's code.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use regex::Regex;
use serde_json::{Value, json};

use appfuzz_core::record::RunRecord;
use appfuzz_core::statics::{ModuleInfo, Statics, disasm};

#[derive(Subcommand)]
pub enum WasmCmd {
    /// The core modules inside the component.
    Info,
    /// Functions of a module (default: the main one).
    Funcs {
        #[arg(long)]
        module: Option<String>,
        /// Only functions that reach a host function.
        #[arg(long)]
        host: bool,
        /// Only names matching this regex.
        #[arg(long)]
        grep: Option<String>,
    },
    /// What a function calls, down to a depth.
    Callgraph {
        func: String,
        #[arg(long)]
        module: Option<String>,
        #[arg(long, default_value_t = 2)]
        depth: usize,
    },
    /// Who calls a function or host function, up to a depth.
    Xrefs {
        /// Function index, name (regex), or host function key.
        target: String,
        #[arg(long)]
        module: Option<String>,
        #[arg(long, default_value_t = 2)]
        depth: usize,
    },
    /// Loops that reach host functions (static n+1 candidates).
    Loops {
        #[arg(long)]
        module: Option<String>,
    },
    /// Strings in data segments.
    Strings {
        #[arg(long)]
        grep: Option<String>,
        #[arg(long, default_value_t = 4)]
        min: usize,
        #[arg(long)]
        module: Option<String>,
    },
    /// A function's instructions.
    Disasm {
        func: String,
        #[arg(long)]
        module: Option<String>,
    },
    /// Where each host function is called from, statically and in runs.
    Sites,
}

fn pick<'a>(s: &'a Statics, module: &Option<String>) -> Result<&'a ModuleInfo> {
    match module {
        Some(m) => s.module(m).ok_or_else(|| anyhow!("no module {m}; see `appfuzz wasm info`")),
        None => s.main().ok_or_else(|| anyhow!("no main module")),
    }
}

/// Function indices matching `index`, `module:index`, a host key, or a name regex.
fn resolve(m: &ModuleInfo, f: &str) -> Result<Vec<u32>> {
    let f = f.rsplit_once(':').filter(|(a, _)| *a == m.id).map(|(_, b)| b).unwrap_or(f);
    if let Ok(i) = f.parse::<u32>() {
        return Ok(vec![i]);
    }
    let hosts: Vec<u32> = m.imports.iter().filter(|i| i.host.as_deref() == Some(f)).filter_map(|i| i.func).collect();
    if !hosts.is_empty() {
        return Ok(hosts);
    }
    let re = Regex::new(f)?;
    let all = (0..m.func_imports + m.funcs.len() as u32).filter(|i| m.func_name(*i).is_some_and(|n| re.is_match(&n))).collect::<Vec<_>>();
    if all.is_empty() {
        bail!("no function matches {f:?}");
    }
    Ok(all)
}

pub fn run(cmd: &WasmCmd, bytes: &[u8], runs: &[RunRecord]) -> Result<Value> {
    let s = Statics::parse(bytes)?;
    Ok(match cmd {
        WasmCmd::Info => json!({"modules": s.modules.iter().map(|m| json!({
            "id": m.id, "index": m.index, "role": m.role, "bytes": m.end - m.start,
            "funcs": m.funcs.len(), "func_imports": m.func_imports, "has_names": m.has_names,
            "host_imports": m.imports.iter().filter_map(|i| i.host.clone()).collect::<Vec<_>>(),
            "other_imports": m.imports.iter().filter(|i| i.host.is_none() && i.kind == "func").map(|i| format!("{}#{}", i.module, i.name)).collect::<Vec<_>>(),
            "exports": m.exports.iter().filter(|e| e.1 == "func").map(|e| &e.0).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()}),
        WasmCmd::Funcs { module, host, grep } => {
            let m = pick(&s, module)?;
            let reach = m.host_reach();
            let re = grep.as_deref().map(Regex::new).transpose()?;
            let funcs: Vec<Value> = m
                .funcs
                .iter()
                .filter(|f| !host || reach.contains_key(&f.index))
                .filter(|f| re.as_ref().is_none_or(|re| re.is_match(&m.label(f.index))))
                .map(|f| {
                    json!({
                        "func": f.index, "name": m.label(f.index), "bytes": f.end - f.start,
                        "calls": f.calls.len(), "call_indirect": f.call_indirect, "loops": f.loops.len(),
                        "reaches_host": reach.get(&f.index).map(|s| s.iter().collect::<Vec<_>>()).unwrap_or_default(),
                    })
                })
                .collect();
            json!({"module": m.id, "count": funcs.len(), "funcs": funcs})
        }
        WasmCmd::Callgraph { func, module, depth } => {
            let m = pick(&s, module)?;
            let roots = resolve(m, func)?;
            json!({"module": m.id, "callgraph": roots.iter().map(|r| tree_down(m, *r, *depth, &mut vec![])).collect::<Vec<_>>()})
        }
        WasmCmd::Xrefs { target, module, depth } => {
            let m = pick(&s, module)?;
            let callers = m.callers();
            let roots = resolve(m, target)?;
            json!({"module": m.id, "xrefs": roots.iter().map(|r| tree_up(m, &callers, *r, *depth, &mut vec![])).collect::<Vec<_>>()})
        }
        WasmCmd::Loops { module } => {
            let m = pick(&s, module)?;
            let reach = m.host_reach();
            let mut out = Vec::new();
            for f in &m.funcs {
                for l in &f.loops {
                    let mut hosts = std::collections::BTreeSet::new();
                    for (c, _) in &l.calls {
                        if let Some(h) = reach.get(c) {
                            hosts.extend(h.iter().cloned());
                        }
                    }
                    if hosts.is_empty() {
                        continue;
                    }
                    let callees: Vec<String> = l
                        .calls
                        .iter()
                        .filter(|(c, _)| reach.contains_key(c))
                        .map(|(c, _)| m.label(*c))
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    out.push(json!({
                        "func": f.index, "name": m.label(f.index), "loop_at": format!("{:x}", l.start), "nesting": l.depth,
                        "hosts": hosts, "via": callees, "indirect_calls_in_loop": l.call_indirect,
                    }));
                }
            }
            json!({"module": m.id, "note": "direct calls only; indirect calls inside a loop may reach more", "loops": out})
        }
        WasmCmd::Strings { grep, min, module } => {
            let re = grep.as_deref().map(Regex::new).transpose()?;
            let mods: Vec<&ModuleInfo> = match module {
                Some(_) => vec![pick(&s, module)?],
                None => s.modules.iter().collect(),
            };
            let mut out = Vec::new();
            for m in mods {
                let data = m.strings.iter().map(|s| (s, "data"));
                let code = m.funcs.iter().flat_map(|f| f.text_consts.iter()).map(|s| (s, "code"));
                for ((off, text), from) in data.chain(code) {
                    if text.chars().count() >= *min && re.as_ref().is_none_or(|re| re.is_match(text)) {
                        out.push(json!({"module": m.id, "at": format!("{off:x}"), "in": from, "text": text}));
                    }
                }
            }
            json!({"count": out.len(), "strings": out})
        }
        WasmCmd::Disasm { func, module } => {
            let m = pick(&s, module)?;
            let f = *resolve(m, func)?.first().expect("non-empty");
            json!({"module": m.id, "func": f, "name": m.label(f), "code": disasm(bytes, &s, &m.id, f)?})
        }
        WasmCmd::Sites => {
            let mut out = serde_json::Map::new();
            for m in &s.modules {
                let callers = m.callers();
                for imp in &m.imports {
                    let (Some(fi), Some(h)) = (imp.func, &imp.host) else { continue };
                    let sites: Vec<Value> = callers
                        .get(&fi)
                        .into_iter()
                        .flatten()
                        .map(|(c, off)| json!({"module": m.id, "func": c, "name": m.label(*c), "at": format!("{off:x}")}))
                        .collect();
                    out.insert(h.clone(), json!({"static_sites": sites}));
                }
            }
            let mut seen: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
            for r in runs {
                for e in &r.events {
                    if let Some(f) = s.app_frame(&e.stack) {
                        *seen.entry(e.func.clone()).or_default().entry(s.frame_name(f)).or_default() += 1;
                    }
                }
            }
            for (h, from) in seen {
                let entry = out.entry(h).or_insert_with(|| json!({"static_sites": []}));
                entry["called_from_in_runs"] = json!(from);
            }
            json!({"runs_used": runs.len(), "host_functions": out})
        }
    })
}

fn tree_down(m: &ModuleInfo, f: u32, depth: usize, path: &mut Vec<u32>) -> Value {
    let mut o = json!({"func": f, "name": m.label(f)});
    if let Some(i) = m.import_of(f) {
        o["import"] = json!(format!("{}#{}", i.module, i.name));
        return o;
    }
    if path.contains(&f) {
        o["recursive"] = json!(true);
        return o;
    }
    let Some(body) = m.func(f) else { return o };
    if body.call_indirect > 0 {
        o["call_indirect"] = json!(body.call_indirect);
    }
    let mut callees: Vec<u32> = body.calls.iter().map(|c| c.0).collect();
    callees.sort();
    callees.dedup();
    if depth == 0 {
        if !callees.is_empty() {
            o["more_callees"] = json!(callees.len());
        }
        return o;
    }
    path.push(f);
    o["calls"] = Value::Array(callees.into_iter().map(|c| tree_down(m, c, depth - 1, path)).collect());
    path.pop();
    o
}

fn tree_up(m: &ModuleInfo, callers: &BTreeMap<u32, Vec<(u32, u64)>>, f: u32, depth: usize, path: &mut Vec<u32>) -> Value {
    let mut o = json!({"func": f, "name": m.label(f)});
    if path.contains(&f) {
        o["recursive"] = json!(true);
        return o;
    }
    let mut cs: Vec<u32> = callers.get(&f).into_iter().flatten().map(|c| c.0).collect();
    cs.sort();
    cs.dedup();
    if cs.is_empty() {
        if m.exports.iter().any(|e| e.1 == "func" && e.2 == f) {
            o["exported"] = json!(true);
        }
        return o;
    }
    if depth == 0 {
        o["more_callers"] = json!(cs.len());
        return o;
    }
    path.push(f);
    o["called_by"] = Value::Array(cs.into_iter().map(|c| tree_up(m, callers, c, depth - 1, path)).collect());
    path.pop();
    o
}
