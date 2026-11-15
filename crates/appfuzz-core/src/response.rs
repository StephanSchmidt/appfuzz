//! `[entry.response]`: a response the platform builds from host calls.
//! An app that answers with `page#set-html(name, html)`,
//! `page#redirect(path)` and `page#set-status(code)` returns nothing; the
//! platform sends what those calls set. appfuzz records the parts as the
//! calls happen (from the complete arguments, before the trace shortens
//! them) and makes them the run's result, `{status, headers, body}`, so
//! output labels and output checks apply as to any other response.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::wit::{FuncInfo, Interface};

/// One field's sources: one, or several where the last call wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Sources {
    One(Source),
    Many(Vec<Source>),
}

impl Sources {
    pub fn all(&self) -> &[Source] {
        match self {
            Sources::One(s) => std::slice::from_ref(s),
            Sources::Many(v) => v,
        }
    }
}

/// Where a response field comes from: a parameter of a host call, a fixed
/// value when a call happens, or (without `call`) a default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The host function whose call sets the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<String>,
    /// The parameter holding the value; by default the function's only one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<String>,
    /// A fixed value instead of an argument: `303` when `redirect` is called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Matchers on the call's arguments, by parameter name: `{ name = "page" }`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub when: BTreeMap<String, Value>,
}

/// A source bound to an imported function, for the interceptor.
#[derive(Debug, Clone)]
pub(crate) struct Bound {
    pub field: String,
    pub arg: Option<String>,
    pub value: Option<Value>,
    pub when: BTreeMap<String, Value>,
}

impl Bound {
    /// The field's new value, if this call sets it.
    pub fn take(&self, args: &[(String, Value)]) -> Option<Value> {
        let arg = |name: &str| args.iter().find(|(n, _)| n == name || n.replace('-', "_") == name).map(|(_, v)| v);
        if !self.when.iter().all(|(p, m)| arg(p).is_some_and(|v| crate::plan::matches(m, v))) {
            return None;
        }
        match (&self.value, &self.arg) {
            (Some(v), _) => Some(v.clone()),
            (None, Some(a)) => arg(a).cloned(),
            (None, None) => args.first().map(|(_, v)| v.clone()),
        }
    }
}

fn field_ok(field: &str) -> bool {
    matches!(field, "status" | "body") || field.strip_prefix("headers.").is_some_and(|h| !h.is_empty() && !h.contains(char::is_whitespace))
}

fn import<'a>(call: &str, imports: &'a [Interface]) -> Option<&'a FuncInfo> {
    let (i, f) = call.split_once('#').unwrap_or(("", call));
    let key = crate::manifest::fn_key(i, f);
    imports.iter().flat_map(|i| &i.funcs).find(|f| f.key == key)
}

/// Checks `[entry.response]` against the imports and binds each source to
/// the function key the interceptor sees. A function the app doesn't
/// import is skipped (a platform describes all of its functions); a
/// misspelling of one it does is an error.
pub(crate) fn bind(response: &BTreeMap<String, Sources>, imports: &[Interface]) -> Result<BTreeMap<String, Vec<Bound>>> {
    let mut out: BTreeMap<String, Vec<Bound>> = BTreeMap::new();
    for (field, sources) in response {
        if !field_ok(field) {
            bail!("entry.response.{field}: a response field is status, body or headers.<name>");
        }
        for (i, s) in sources.all().iter().enumerate() {
            let at = format!("entry.response.{field}[{i}]");
            let Some(call) = &s.call else {
                if s.value.is_none() || s.arg.is_some() || !s.when.is_empty() {
                    bail!("{at}: without `call` a source is a default and needs `value` only");
                }
                continue;
            };
            if s.value.is_some() && s.arg.is_some() {
                bail!("{at}: `value` or `arg`, not both");
            }
            let Some(f) = import(call, imports) else {
                if let Some((_, real)) = crate::labels::misspelling(std::slice::from_ref(call), imports) {
                    bail!("{at}: the app imports no {call}: did you mean {real}?");
                }
                continue;
            };
            let params: Vec<String> = f.ty.params().map(|(n, _)| n.to_string()).collect();
            let named = |p: &str| params.iter().any(|n| n == p || n.replace('-', "_") == p);
            if let Some(a) = &s.arg
                && !named(a)
            {
                bail!("{at}: {} has no parameter {a}", f.signature());
            }
            if s.arg.is_none() && s.value.is_none() && params.len() != 1 {
                bail!("{at}: {} takes {} parameters; name one with `arg`", f.signature(), params.len());
            }
            for (p, m) in &s.when {
                if !named(p) {
                    bail!("{at}: `when` names {p}, but {} has no such parameter", f.signature());
                }
                crate::plan::matcher_ok(m).map_err(|e| anyhow::anyhow!("{at}: when {p}: {e:#}"))?;
            }
            out.entry(f.key.clone()).or_default().push(Bound { field: field.clone(), arg: s.arg.clone(), value: s.value.clone(), when: s.when.clone() });
        }
    }
    Ok(out)
}

/// Text from an argument: a string as it is, bytes as UTF-8, an option's
/// value, anything else as JSON.
fn text(v: &Value) -> Value {
    match v {
        Value::Object(o) if o.len() == 1 && o.contains_key("some") => text(&o["some"]),
        Value::String(_) | Value::Null => v.clone(),
        Value::Array(a) if a.iter().all(|x| x.as_u64().is_some_and(|n| n < 256)) => {
            let bytes: Vec<u8> = a.iter().filter_map(Value::as_u64).map(|n| n as u8).collect();
            Value::String(String::from_utf8_lossy(&bytes).into_owned())
        }
        x => Value::String(x.to_string()),
    }
}

fn status(v: &Value) -> Value {
    match v {
        Value::Object(o) if o.len() == 1 && o.contains_key("some") => status(&o["some"]),
        Value::String(s) => s.trim().parse::<u64>().map(Value::from).unwrap_or_else(|_| v.clone()),
        x => x.clone(),
    }
}

/// The response: defaults first, then the parts in call order, the last
/// one per field winning. What the export returned, if anything, stays
/// under `return`.
pub(crate) fn build(response: &BTreeMap<String, Sources>, parts: &[(String, Value)], returned: Option<Value>) -> Value {
    let defaults = response.iter().flat_map(|(f, s)| s.all().iter().filter(|s| s.call.is_none()).filter_map(move |s| Some((f.clone(), s.value.clone()?))));
    let mut out = serde_json::Map::new();
    let mut headers: Vec<(String, Value)> = Vec::new();
    for (field, v) in defaults.collect::<Vec<_>>().into_iter().chain(parts.iter().cloned()) {
        match field.as_str() {
            "status" => {
                out.insert("status".into(), status(&v));
            }
            "body" => {
                out.insert("body".into(), text(&v));
            }
            h => {
                let name = h.trim_start_matches("headers.").to_ascii_lowercase();
                headers.retain(|(n, _)| *n != name);
                headers.push((name, text(&v)));
            }
        }
    }
    out.insert("headers".into(), Value::Array(headers.into_iter().map(|(n, v)| json!([n, v])).collect()));
    if let Some(r) = returned.filter(|r| !r.is_null()) {
        out.insert("return".into(), r);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(toml_text: &str) -> BTreeMap<String, Sources> {
        toml::from_str::<BTreeMap<String, Sources>>(toml_text).unwrap()
    }

    #[test]
    fn the_last_call_wins_over_defaults() {
        let r = sources(
            r#"
            status = [{ value = 200 }, { call = "a:b/page#set-status", arg = "code" }, { call = "a:b/page#redirect", value = 303 }]
            body = { call = "a:b/page#set-html", arg = "html", when = { name = "page" } }
            "headers.Location" = { call = "a:b/page#redirect" }
            "#,
        );
        let parts = vec![("body".to_string(), json!("<p>a</p>")), ("headers.Location".to_string(), json!("/x")), ("status".to_string(), json!(303))];
        let v = build(&r, &parts, None);
        assert_eq!(v, json!({"status": 303, "body": "<p>a</p>", "headers": [["location", "/x"]]}));
        assert_eq!(build(&r, &[], Some(json!(7))), json!({"status": 200, "headers": [], "return": 7}));
        // Bytes are text; a status may come as text.
        let v = build(&r, &[("body".into(), json!([104, 105])), ("status".into(), json!("404"))], None);
        assert_eq!((&v["body"], &v["status"]), (&json!("hi"), &json!(404)));
    }

    #[test]
    fn a_source_takes_its_argument_when_the_call_matches() {
        let b = Bound { field: "body".into(), arg: Some("html".into()), value: None, when: [("name".to_string(), json!("page"))].into() };
        let args = |name: &str| vec![("name".to_string(), json!(name)), ("html".to_string(), json!("<b>x</b>"))];
        assert_eq!(b.take(&args("page")), Some(json!("<b>x</b>")));
        assert_eq!(b.take(&args("sidebar")), None);
        let fixed = Bound { field: "status".into(), arg: None, value: Some(json!(303)), when: BTreeMap::new() };
        assert_eq!(fixed.take(&args("x")), Some(json!(303)));
    }
}
