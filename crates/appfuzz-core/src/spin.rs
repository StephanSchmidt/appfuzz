//! `spin.toml`: a Spin app reviewed without `appfuzz.toml`.
//!
//! The Spin manifest already says what the platform grants one component:
//! the hosts it may call (`allowed_outbound_hosts`), the key-value stores
//! and SQLite databases it may open, and its variables, some of them
//! secret. appfuzz turns that into grants, platform rules (opening another
//! store is `access-denied`, an undeclared variable is `undefined`) and
//! labels (a secret variable is traced as a secret). Spin links all of WASI
//! and its own interfaces, so there is no import grant list.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::labels::{Label, ResultLabels};
use crate::manifest::{Entry, FunctionSpec, Manifest};
use crate::plan::{Response, Rule};

#[derive(Deserialize)]
struct SpinToml {
    spin_manifest_version: Option<toml::Value>,
    #[serde(default)]
    application: Application,
    #[serde(default)]
    variables: BTreeMap<String, AppVariable>,
    #[serde(default)]
    trigger: BTreeMap<String, Vec<Trigger>>,
    #[serde(default)]
    component: BTreeMap<String, Component>,
}

#[derive(Deserialize, Default)]
struct Application {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize, Default)]
struct AppVariable {
    default: Option<String>,
    #[serde(default)]
    secret: bool,
}

#[derive(Deserialize)]
struct Trigger {
    route: Option<toml::Value>,
    component: Option<toml::Value>,
}

#[derive(Deserialize)]
struct Component {
    source: toml::Value,
    #[serde(default)]
    allowed_outbound_hosts: Vec<String>,
    #[serde(default)]
    key_value_stores: Vec<String>,
    #[serde(default)]
    sqlite_databases: Vec<String>,
    #[serde(default)]
    variables: BTreeMap<String, String>,
}

/// Whether a manifest path is a Spin manifest.
pub fn is_spin(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "spin.toml")
}

/// The appfuzz manifest for one component of a Spin app: `component`, or
/// the only one with an HTTP trigger.
pub fn load(path: &Path, component: Option<&str>) -> Result<Manifest> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    from_str(&text, &dir, component).with_context(|| format!("in {}", path.display()))
}

fn from_str(text: &str, dir: &Path, component: Option<&str>) -> Result<Manifest> {
    let spin: SpinToml = toml::from_str(text).context("parsing the Spin manifest")?;
    match spin.spin_manifest_version.as_ref().and_then(|v| v.as_integer().or_else(|| v.as_str().and_then(|s| s.parse().ok()))) {
        Some(2) => {}
        _ => bail!("only Spin manifest version 2 is supported (spin_manifest_version = 2); `spin doctor` upgrades older ones"),
    }
    // HTTP triggers: the component they name and its route.
    let mut routes: BTreeMap<String, String> = BTreeMap::new();
    for t in spin.trigger.get("http").into_iter().flatten() {
        if let Some(c) = t.component.as_ref().and_then(|c| c.as_str()) {
            let route = t.route.as_ref().and_then(|r| r.as_str()).unwrap_or("/...").to_string();
            routes.entry(c.to_string()).or_insert(route);
        }
    }
    let id = match component {
        Some(c) if spin.component.contains_key(c) => c.to_string(),
        Some(c) => bail!("no component {c:?}; the components are {}", names(spin.component.keys())),
        None if routes.len() == 1 => routes.keys().next().cloned().unwrap_or_default(),
        None if routes.is_empty() && spin.component.len() == 1 => spin.component.keys().next().cloned().unwrap_or_default(),
        None if routes.is_empty() => bail!("no HTTP trigger; pick a component with --component ({})", names(spin.component.keys())),
        None => bail!("several HTTP components; pick one with --component ({})", names(routes.keys())),
    };
    let c = &spin.component[&id];
    let wasm = match &c.source {
        toml::Value::String(s) => PathBuf::from(s),
        _ => bail!("component {id:?}: source must be a local .wasm path (download a registry or URL source first)"),
    };

    let mut m = Manifest::for_wasm(&wasm);
    m.dir = dir.to_path_buf();
    m.app.name = Some(spin.application.name.clone().unwrap_or_else(|| id.clone()));
    m.app.description.clone_from(&spin.application.description);
    let route = routes.get(&id).cloned().unwrap_or_else(|| "/...".into());
    let base = route.trim_end_matches("...").trim_end_matches('/').to_string();
    if !base.is_empty() {
        m.app.base = Some(base.clone());
    }
    if routes.contains_key(&id) {
        m.entry = Some(Entry {
            export: "wasi:http/incoming-handler#handle".into(),
            request: Some(json!({ "method": "GET", "uri": format!("https://app.example{base}/"), "headers": [], "body": "" })),
            fields: Default::default(),
            output: Default::default(),
            now: None,
            result: Default::default(),
            sensitive_paths: vec![],
            csp: None,
            no_pii: false,
            values: Default::default(),
            input_values: Default::default(),
        });
    }

    // Variables: what `get` answers for each name the component declares.
    let resolve = |template: &str| -> (Option<String>, bool) { render(template, &spin.variables) };
    let mut var_rules = Vec::new();
    for (name, template) in &c.variables {
        let (value, secret) = resolve(template);
        let when = BTreeMap::from([("name".to_string(), json!(name))]);
        if secret {
            var_rules.push(Rule { when, result: Some(ResultLabels::Whole(Label::Secret)), ..Default::default() });
        } else if let Some(v) = value {
            var_rules.push(Rule { when, response: Response { ret: Some(json!({ "ok": v })), ..Default::default() }, result: None });
        }
    }
    let declared = alternatives(c.variables.keys());
    let undefined = |err: Value| Rule { when: not_one_of("name", &declared), response: Response { ret: Some(err), ..Default::default() }, result: None };
    for key in ["fermyon:spin/variables#get", "spin:variables/variables#get"] {
        let mut rules = var_rules.clone();
        rules.push(undefined(json!({ "err": { "undefined": "no such variable" } })));
        m.functions.insert(key.into(), FunctionSpec { rules, ..Default::default() });
    }
    // wasi:config/store (Spin 3): an undefined key is `none`, the key is `key`.
    let mut rules: Vec<Rule> = var_rules
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.when = BTreeMap::from([("key".to_string(), r.when["name"].clone())]);
            r
        })
        .collect();
    rules.push(Rule { when: not_one_of("key", &declared), response: Response { ret: Some(json!({ "ok": null })), ..Default::default() }, result: None });
    m.functions.insert("wasi:config/store#get".into(), FunctionSpec { rules, ..Default::default() });

    // Stores and databases the component may open; the others are denied.
    let denied = |param: &str, allowed: &[String]| {
        vec![Rule {
            when: not_one_of(param, &alternatives(allowed.iter())),
            response: Response { ret: Some(json!({ "err": "access-denied" })), ..Default::default() },
            result: None,
        }]
    };
    for key in ["fermyon:spin/key-value#[static]store.open", "spin:key-value/key-value#[static]store.open"] {
        m.functions.insert(key.into(), FunctionSpec { rules: denied("label", &c.key_value_stores), ..Default::default() });
    }
    m.functions.insert("wasi:keyvalue/store#open".into(), FunctionSpec { rules: denied("identifier", &c.key_value_stores), ..Default::default() });
    for key in ["fermyon:spin/sqlite#[static]connection.open", "spin:sqlite/sqlite#[static]connection.open"] {
        m.functions.insert(key.into(), FunctionSpec { rules: denied("database", &c.sqlite_databases), ..Default::default() });
    }

    // Outbound requests: Spin refuses a URL no entry allows, before it
    // leaves. An entry only Spin can resolve leaves the list unknown.
    let allowed: Option<Vec<String>> = c.allowed_outbound_hosts.iter().map(|h| fill(h, &spin.variables, &c.variables).map(|e| url_pattern(&e))).collect();
    if let Some(allowed) = allowed {
        let when = if allowed.is_empty() { json!({ "any": true }) } else { json!({ "not": { "regex": format!("(?i)^(?:{})", allowed.join("|")) } }) };
        let rule = Rule {
            when: BTreeMap::from([("url".to_string(), when)]),
            response: Response { ret: Some(json!({ "err": "http-request-denied" })), ..Default::default() },
            result: None,
        };
        m.functions.insert(crate::wasi_http::CLIENT_KEY.into(), FunctionSpec { rules: vec![rule], ..Default::default() });
    }

    let mut hosts: Vec<String> = c.allowed_outbound_hosts.iter().filter_map(|h| host(h, &spin.variables, &c.variables)).collect();
    hosts.sort();
    hosts.dedup();
    // Declared even when empty: Spin then refuses every request.
    m.grants.hosts = Some(hosts);
    Ok(m)
}

fn names<'a>(it: impl Iterator<Item = &'a String>) -> String {
    it.map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")
}

/// A regex alternation that matches exactly these names.
fn alternatives<'a>(it: impl Iterator<Item = &'a String>) -> Vec<String> {
    it.map(|s| regex::escape(s)).collect()
}

/// A `when` for a parameter that is none of these names.
fn not_one_of(param: &str, names: &[String]) -> BTreeMap<String, Value> {
    let m = if names.is_empty() { json!({ "any": true }) } else { json!({ "not": { "regex": format!("^(?:{})$", names.join("|")) } }) };
    BTreeMap::from([(param.to_string(), m)])
}

/// A component variable's value, if known, and whether it is a secret: a
/// template that uses a secret application variable is one.
fn render(template: &str, app: &BTreeMap<String, AppVariable>) -> (Option<String>, bool) {
    let mut out = String::new();
    let mut known = true;
    let mut secret = false;
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else { break };
        let name = rest[i + 2..i + j].trim();
        match app.get(name) {
            Some(v) => {
                secret |= v.secret;
                match &v.default {
                    Some(d) => out.push_str(d),
                    None => known = false,
                }
            }
            None => known = false,
        }
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    (known.then_some(out), secret)
}

/// An `allowed_outbound_hosts` entry with its `{{ name }}` component
/// variables filled in; `None` when only Spin can resolve one.
fn fill(entry: &str, app: &BTreeMap<String, AppVariable>, vars: &BTreeMap<String, String>) -> Option<String> {
    let mut s = entry.to_string();
    for (name, template) in vars {
        for pat in [format!("{{{{ {name} }}}}"), format!("{{{{{name}}}}}")] {
            if s.contains(&pat) {
                s = s.replace(&pat, &render(template, app).0?);
            }
        }
    }
    (!s.contains("{{")).then_some(s)
}

/// A regex for the URLs an `allowed_outbound_hosts` entry lets through
/// (`scheme://host[:port]`; `*` for any scheme, host or port, `*.x` for
/// x's subdomains, `self` for the app itself). Without a port, the
/// scheme's default port.
fn url_pattern(entry: &str) -> String {
    let (scheme, rest) = entry.split_once("://").unwrap_or(("*", entry));
    let auth = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = if auth.starts_with('[') {
        let end = auth.find(']').map_or(auth.len(), |i| i + 1);
        (&auth[..end], auth[end..].strip_prefix(':'))
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (auth, None),
        }
    };
    let scheme_re = if scheme == "*" { "[a-z][a-z0-9+.-]*".to_string() } else { regex::escape(scheme) };
    let host_re = match host {
        "*" => r"[^/?#@:\[\]]+".to_string(),
        "self" => r"self(?:\.alt)?".to_string(),
        h if h.starts_with("*.") => format!(r"(?:[^/?#@:]+\.)?{}", regex::escape(&h[2..])),
        h => regex::escape(h),
    };
    let default = match scheme {
        "https" => "443",
        "http" => "80",
        _ => r"(?:80|443)",
    };
    let port_re = match port {
        None => format!("(?::{default})?"),
        Some(p) if p == "*" || p.contains('-') => r"(?::\d+)?".to_string(),
        Some(p) if p == default => format!("(?::{p})?"),
        Some(p) => format!(":{}", regex::escape(p)),
    };
    format!("{scheme_re}://(?:[^/?#@]*@)?{host_re}{port_re}(?:[/?#]|$)")
}

/// The host an `allowed_outbound_hosts` entry grants: `https://api.example.com`,
/// `https://*.example.com:443`, `*://*:*` (any host). `self` is the app
/// itself, and an entry that only Spin can resolve is skipped.
fn host(entry: &str, app: &BTreeMap<String, AppVariable>, vars: &BTreeMap<String, String>) -> Option<String> {
    let entry = fill(entry, app, vars)?;
    let rest = entry.split_once("://").map(|(_, r)| r).unwrap_or(&entry);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = if host.starts_with('[') { host.split_inclusive(']').next().unwrap_or(host) } else { host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host) };
    match host {
        "" | "self" | "localhost" => None,
        h => Some(h.to_ascii_lowercase()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = r#"
spin_manifest_version = 2

[application]
name = "shop"

[variables]
api_token = { required = true, secret = true }
api_host = { default = "api.example.com" }
greeting = { default = "Hello" }

[[trigger.http]]
route = "/shop/..."
component = "web"

[component.web]
source = "target/wasm32-wasip2/release/web.wasm"
allowed_outbound_hosts = ["https://{{ host }}", "https://*.cdn.example:443", "http://self", "redis://cache.internal:6379"]
key_value_stores = ["default"]
sqlite_databases = ["default"]

[component.web.variables]
token = "Bearer {{ api_token }}"
host = "{{ api_host }}"
greeting = "{{ greeting }}, world"
"#;

    #[test]
    fn reads_a_spin_app() {
        let m = from_str(APP, Path::new("/app"), None).unwrap();
        assert_eq!(m.wasm_path(), PathBuf::from("/app/target/wasm32-wasip2/release/web.wasm"));
        assert_eq!(m.app.name.as_deref(), Some("shop"));
        assert_eq!(m.app.base.as_deref(), Some("/shop"));
        assert_eq!(m.grants.hosts.unwrap(), vec!["*.cdn.example", "api.example.com", "cache.internal"]);
        let get = |name: &str| vec![("name".to_string(), json!(name))];
        let vars = &m.functions["fermyon:spin/variables#get"];
        assert_eq!(crate::plan::result_labels_for(None, &vars.rules, &get("token")), vec![(String::new(), Label::Secret)]);
        assert!(crate::plan::result_labels_for(None, &vars.rules, &get("greeting")).is_empty());
        let answer = |name: &str| crate::plan::resolve_rules(&vars.rules, &get(name), None).map(|r| format!("{:?}", r.decision));
        assert_eq!(answer("greeting").as_deref(), Some(r#"Return(Object {"ok": String("Hello, world")})"#));
        assert!(answer("token").is_none(), "a secret is generated, as a traceable secret");
        assert!(answer("nope").unwrap().contains("undefined"));
        let open = &m.functions["fermyon:spin/key-value#[static]store.open"];
        let label = |l: &str| crate::plan::resolve_rules(&open.rules, &[("label".to_string(), json!(l))], None).is_some();
        assert!(!label("default"));
        assert!(label("other"));
        let open = &m.functions["wasi:keyvalue/store#open"];
        let opens = |l: &str| crate::plan::resolve_rules(&open.rules, &[("identifier".to_string(), json!(l))], None).is_none();
        assert!(opens("default") && !opens("other"));
        let out = &m.functions[crate::wasi_http::CLIENT_KEY];
        let denied = |url: &str| crate::plan::resolve_rules(&out.rules, &[("url".to_string(), json!(url))], None).is_some();
        for ok in
            ["https://api.example.com/x", "https://API.example.com:443?q", "https://img.cdn.example/a.png", "http://self/admin", "https://u@api.example.com/"]
        {
            assert!(!denied(ok), "{ok}");
        }
        for no in [
            "http://api.example.com/",
            "https://api.example.com:8443/",
            "https://api.example.com.evil.example/",
            "https://169.254.169.254/",
            "https://x@evil.example/",
        ] {
            assert!(denied(no), "{no}");
        }
    }

    #[test]
    fn outbound_hosts_spin_cannot_resolve_deny_nothing() {
        let any = APP.replace("\"https://{{ host }}\"", "\"https://{{ unknown }}\"");
        let m = from_str(&any, Path::new("."), None).unwrap();
        assert!(!m.functions.contains_key(crate::wasi_http::CLIENT_KEY));
        let all = APP.replace("allowed_outbound_hosts = [", "allowed_outbound_hosts = [\"*://*:*\", ");
        let m = from_str(&all, Path::new("."), None).unwrap();
        let out = &m.functions[crate::wasi_http::CLIENT_KEY];
        assert!(crate::plan::resolve_rules(&out.rules, &[("url".to_string(), json!("http://10.0.0.1:8080/"))], None).is_none());
    }

    #[test]
    fn picks_the_component() {
        let two = format!("{APP}\n[[trigger.http]]\nroute = \"/admin/...\"\ncomponent = \"admin\"\n[component.admin]\nsource = \"admin.wasm\"\n");
        assert!(from_str(&two, Path::new("."), None).unwrap_err().to_string().contains("--component"));
        let m = from_str(&two, Path::new("."), Some("admin")).unwrap();
        assert_eq!(m.grants.hosts, Some(vec![]));
        let out = &m.functions[crate::wasi_http::CLIENT_KEY];
        assert!(crate::plan::resolve_rules(&out.rules, &[("url".to_string(), json!("https://api.example.com/"))], None).is_some(), "no host granted");
        let open = &m.functions["fermyon:spin/sqlite#[static]connection.open"];
        assert!(crate::plan::resolve_rules(&open.rules, &[("database".to_string(), json!("default"))], None).is_some(), "no database granted");
        assert!(from_str("spin_version = \"1\"", Path::new("."), None).is_err());
    }
}
