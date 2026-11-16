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
    let count = m.func_imports + m.funcs.len() as u32;
    if let Ok(i) = f.parse::<u32>() {
        if i >= count {
            bail!("{} has no function {i} (it has {count}, numbered from 0); see `appfuzz wasm funcs`", m.id);
        }
        return Ok(vec![i]);
    }
    let hosts: Vec<u32> = m.imports.iter().filter(|i| i.host.as_deref() == Some(f)).filter_map(|i| i.func).collect();
    if !hosts.is_empty() {
        return Ok(hosts);
    }
    let re = Regex::new(f)?;
    let all = (0..count).filter(|i| m.func_name(*i).is_some_and(|n| re.is_match(&n))).collect::<Vec<_>>();
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

#[cfg(test)]
mod tests {
    use super::*;
    use appfuzz_core::record::{Frame, HostCall};

    /// get 0 and log 1 are imports; fetch 2, again 3, dispatch 4, run 5, orphan 6.
    const WAT: &str = r#"(module
      (import "test:dig/db" "get" (func $get (param i32) (result i32)))
      (import "env" "log" (func $log (param i32)))
      (type $t (func (param i32) (result i32)))
      (table 1 funcref)
      (memory 1)
      (data (i32.const 16) "fetchUsers\00ok\00view_mode")
      (func $fetch (param i32) (result i32) (call $get (local.get 0)))
      (func $again (param i32) (result i32) (call $again (local.get 0)))
      (func $dispatch (param i32) (result i32) (call_indirect (type $t) (local.get 0) (i32.const 0)))
      (func $run (export "run") (param i32) (result i32)
        (call $log (local.get 0))
        (drop (call $dispatch (local.get 0)))
        (drop (call $again (local.get 0)))
        (if (i32.eq (local.get 0) (i32.const 0x6b636162)) (then nop))
        (call $fetch (local.get 0)))
      (func $orphan))"#;

    fn module() -> (Vec<u8>, Statics) {
        let bytes = wat::parse_str(WAT).unwrap();
        let statics = Statics::parse(&bytes).unwrap();
        (bytes, statics)
    }

    fn error<T: std::fmt::Debug>(r: Result<T>) -> String {
        r.unwrap_err().to_string()
    }

    #[test]
    fn functions_resolve_by_index_module_index_host_key_and_name() {
        let (_, s) = module();
        let m = s.main().unwrap();
        assert_eq!(resolve(m, "5").unwrap(), [5]);
        assert_eq!(resolve(m, &format!("{}:2", m.id)).unwrap(), [2]);
        assert_eq!(resolve(m, "test:dig/db#get").unwrap(), [0]);
        // Names are regular expressions; other imports are named `module#name`.
        assert_eq!(resolve(m, "^(fetch|again)$").unwrap(), [2, 3]);
        assert_eq!(resolve(m, "env#log").unwrap(), [1]);
        assert_eq!(error(resolve(m, "nosuch")), "no function matches \"nosuch\"");
        assert!(error(resolve(m, "(")).contains("unclosed group"));
        // Another module's prefix is no index into this one.
        assert_eq!(error(resolve(m, "m000000:2")), "no function matches \"m000000:2\"");
    }

    #[test]
    fn an_index_past_the_last_function_is_an_error() {
        let (_, s) = module();
        let m = s.main().unwrap();
        assert_eq!(resolve(m, "6").unwrap(), [6]);
        let e = error(resolve(m, "7"));
        assert_eq!(e, format!("{} has no function 7 (it has 7, numbered from 0); see `appfuzz wasm funcs`", m.id));
        assert!(error(resolve(m, &format!("{}:99", m.id))).contains("has no function 99"));
    }

    #[test]
    fn modules_are_picked_by_id_or_index() {
        let (_, s) = module();
        let main = s.main().unwrap();
        assert_eq!(pick(&s, &None).unwrap().id, main.id);
        assert_eq!(pick(&s, &Some("0".into())).unwrap().id, main.id);
        assert_eq!(pick(&s, &Some(main.id.clone())).unwrap().id, main.id);
        assert_eq!(error(pick(&s, &Some("nope".into()))), "no module nope; see `appfuzz wasm info`");
        assert_eq!(error(pick(&Statics { modules: vec![] }, &None)), "no main module");
    }

    #[test]
    fn callees_stop_at_imports_recursion_and_depth() {
        let (_, s) = module();
        let m = s.main().unwrap();
        assert_eq!(
            tree_down(m, 5, 1, &mut vec![]),
            json!({"func": 5, "name": "run", "calls": [
                {"func": 1, "name": "env#log", "import": "env#log"},
                {"func": 2, "name": "fetch", "more_callees": 1},
                {"func": 3, "name": "again", "more_callees": 1},
                {"func": 4, "name": "dispatch", "call_indirect": 1},
            ]})
        );
        assert_eq!(tree_down(m, 3, 2, &mut vec![]), json!({"func": 3, "name": "again", "calls": [{"func": 3, "name": "again", "recursive": true}]}));
        assert_eq!(tree_down(m, 2, 5, &mut vec![])["calls"], json!([{"func": 0, "name": "test:dig/db#get", "import": "test:dig/db#get"}]));
        // An index without a body (resolve rejects it first) has no callees.
        assert_eq!(tree_down(m, 40, 2, &mut vec![]), json!({"func": 40, "name": format!("{}:40", m.id)}));
    }

    #[test]
    fn callers_stop_at_exports_recursion_and_depth() {
        let (_, s) = module();
        let m = s.main().unwrap();
        let callers = m.callers();
        assert_eq!(
            tree_up(m, &callers, 0, 2, &mut vec![]),
            json!({"func": 0, "name": "test:dig/db#get", "called_by": [
                {"func": 2, "name": "fetch", "called_by": [{"func": 5, "name": "run", "exported": true}]}
            ]})
        );
        assert_eq!(
            tree_up(m, &callers, 3, 2, &mut vec![]),
            json!({"func": 3, "name": "again", "called_by": [
                {"func": 3, "name": "again", "recursive": true},
                {"func": 5, "name": "run", "exported": true},
            ]})
        );
        assert_eq!(tree_up(m, &callers, 2, 0, &mut vec![]), json!({"func": 2, "name": "fetch", "more_callers": 1}));
        // Neither called nor exported.
        assert_eq!(tree_up(m, &callers, 6, 2, &mut vec![]), json!({"func": 6, "name": "orphan"}));
    }

    #[test]
    fn info_and_strings_of_a_core_module() {
        let (bytes, s) = module();
        let id = s.main().unwrap().id.clone();
        let info = run(&WasmCmd::Info, &bytes, &[]).unwrap();
        assert_eq!(info["modules"].as_array().unwrap().len(), 1);
        let m = &info["modules"][0];
        assert_eq!(m["role"], "main");
        assert_eq!(m["host_imports"], json!(["test:dig/db#get"]));
        assert_eq!(m["other_imports"], json!(["env#log"]));
        assert_eq!(m["exports"], json!(["run"]));
        assert_eq!((m["funcs"].as_u64(), m["func_imports"].as_u64(), m["has_names"].as_bool()), (Some(5), Some(2), Some(true)));
        let strings = |grep: Option<&str>, min: usize| {
            let v = run(&WasmCmd::Strings { grep: grep.map(str::to_string), min, module: None }, &bytes, &[]).unwrap();
            assert_eq!(v["count"].as_u64().unwrap() as usize, v["strings"].as_array().unwrap().len());
            v["strings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| (x["in"].as_str().unwrap().to_string(), x["text"].as_str().unwrap().to_string()))
                .collect::<Vec<_>>()
        };
        let all = strings(None, 4);
        assert!(all.contains(&("data".into(), "fetchUsers".into())), "{all:?}");
        assert!(all.contains(&("data".into(), "view_mode".into())), "{all:?}");
        // An integer constant that reads as text: 0x6b636162 is "back".
        assert!(all.contains(&("code".into(), "back".into())), "{all:?}");
        assert_eq!(strings(Some("^view"), 4), [("data".to_string(), "view_mode".to_string())]);
        assert!(!strings(None, 5).iter().any(|(_, t)| t == "back"));
        let one = run(&WasmCmd::Strings { grep: None, min: 4, module: Some(id) }, &bytes, &[]).unwrap();
        assert_eq!(one["count"].as_u64().unwrap() as usize, all.len());
        assert!(run(&WasmCmd::Strings { grep: Some("[".into()), min: 4, module: None }, &bytes, &[]).is_err());
        assert!(run(&WasmCmd::Info, b"not wasm", &[]).is_err());
    }

    #[test]
    fn sites_count_the_app_frames_of_stored_runs() {
        let (bytes, s) = module();
        let id = s.main().unwrap().id.clone();
        let frame = |func: u32| Frame { module: id.clone(), func, name: None, offset: None };
        let mut record: RunRecord = serde_json::from_value(json!({
            "id": "r1", "outcome": {"kind": "ok"}, "events": [],
            "spec": {"component": "c", "export": "run", "args": [1], "now": "2026-01-15T10:00:00", "seed": 1, "fuel": 1, "memory": 1, "ns_per_fuel": 1.0},
            "totals": {"fuel": 0, "peak_memory": 0, "virtual_ns": 0, "guest_ns": 0, "host_ns": 0, "sleep_ns": 0, "host_calls": 0, "cost": 0,
                       "clock_reads": 0, "random_bytes": 0, "wall_us": 0},
        }))
        .unwrap();
        let call = |n: u32, func: &str, stack: Vec<Frame>| HostCall { n, func: func.into(), stack, ..Default::default() };
        record.events = vec![
            call(1, "test:dig/db#get", vec![frame(2), frame(5)]),
            call(2, "test:dig/db#get", vec![frame(2), frame(5)]),
            // A host function the code doesn't import under that name.
            call(3, "other:pkg/svc#send", vec![frame(5)]),
            // No guest frame: nothing to count.
            call(4, "test:dig/db#get", vec![]),
        ];
        let sites = run(&WasmCmd::Sites, &bytes, &[record]).unwrap();
        assert_eq!(sites["runs_used"], 1);
        let get = &sites["host_functions"]["test:dig/db#get"];
        assert_eq!(get["static_sites"].as_array().unwrap().len(), 1);
        assert_eq!(get["static_sites"][0]["name"], "fetch");
        assert_eq!(get["called_from_in_runs"], json!({"fetch": 2}));
        assert_eq!(sites["host_functions"]["other:pkg/svc#send"], json!({"static_sites": [], "called_from_in_runs": {"run": 1}}));
        // `env#log` is no host function: no entry.
        assert_eq!(sites["host_functions"].as_object().unwrap().len(), 2);
    }
}
