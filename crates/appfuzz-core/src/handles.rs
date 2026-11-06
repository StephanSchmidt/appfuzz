//! Handles with state, for platforms whose host functions pass handles
//! (Fastly: requests, responses, bodies).
//!
//! A run keeps a table of the handles the host gave out. Ids are 1, 2, … in
//! creation order, so records replay. Each handle has a JSON state and
//! bytes (a body). `platform.toml` binds host functions to generic
//! operations on that state (`get`, `set`, `map_get`, `read`, `write`, …);
//! nothing platform-specific lives here. A call with a handle the table
//! doesn't hold gets the platform's bad-handle error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// What a host function does to handle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub op: Op,
    /// The state field (`uri`, `headers`, `status`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The parameter naming the handle; default: the first handle parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// The parameter with the map key (a header name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The parameter with the value to store; default: the first parameter
    /// that is not a handle or the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `new` and `downstream`: the kind of handle created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `downstream`: the kind of the body handle created with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_kind: Option<String>,
    /// `respond`: the parameter with the body handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// `respond`: a nonzero parameter keeps the body writable after sending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<String>,
    /// `respond`: sending consumes the response and, unless streaming, its body.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consume: bool,
    /// The platform error for unsupported stream reads or front writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// A new handle of `kind` with its initial state.
    New,
    Get,
    Set,
    /// The first value of `key` in the pair list `field` (case-insensitive).
    MapGet,
    /// Every value of `key`.
    MapValues,
    /// The distinct keys, in order.
    MapKeys,
    /// Replaces every value of `key`.
    MapInsert,
    MapAppend,
    MapRemove,
    /// The next bytes of a body, at most what the guest's buffer holds.
    Read,
    /// Adds bytes to a body (`end` = `front` puts them first).
    Write,
    /// Moves the bytes of the second handle to the end of the first.
    Append,
    Close,
    /// Closes a body unsuccessfully, preserving an incomplete sent prefix.
    Abandon,
    /// The client request (the run's request argument) as a new request
    /// handle and body handle.
    Downstream,
    /// Sends a response handle and body handle as the run's result.
    Respond,
}

/// A handle kind's initial state, from `[handles.KIND]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kind {
    #[serde(default)]
    pub init: Value,
}

#[derive(Debug, Clone)]
struct Entry {
    kind: String,
    state: Value,
    bytes: Vec<u8>,
    offset: usize,
    open: bool,
}

/// What an operation needs from the run.
pub struct Ctx<'a> {
    pub kinds: &'a BTreeMap<String, Kind>,
    /// The run's request argument.
    pub request: Option<&'a Value>,
    /// The most bytes a `read` may return (the guest's buffer).
    pub read_limit: Option<usize>,
    /// The platform's error names.
    pub bad: &'a str,
    pub absent: &'a str,
}

#[derive(Debug, Default)]
pub struct Handles {
    entries: BTreeMap<u32, Entry>,
    /// The response sent by `respond`.
    pub response: Option<Value>,
    stream: Option<SentStream>,
    next: u32,
}

#[derive(Debug)]
struct SentStream {
    body: u32,
    complete: bool,
}

/// A text from a WIT value: a string, or bytes as UTF-8.
pub fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => String::from_utf8_lossy(&bytes(a)).into_owned(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn bytes(a: &[Value]) -> Vec<u8> {
    a.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect()
}

fn pairs(v: &Value) -> Vec<(String, Value)> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| match p.as_array().map(Vec::as_slice) {
            Some([k, v]) => Some((text(k), v.clone())),
            _ => None,
        })
        .collect()
}

impl Handles {
    pub fn valid(&self, id: u32) -> bool {
        self.entries.get(&id).is_some_and(|e| e.open)
    }

    fn is_streaming(&self, id: Option<u32>) -> bool {
        self.stream.as_ref().is_some_and(|s| Some(s.body) == id && self.valid(s.body))
    }

    /// Capture a sent stream after all guest writes, including a failed run.
    /// The response header snapshot remains the one sent at `respond`.
    pub fn take_response(&mut self) -> (Option<Value>, bool) {
        let mut out = self.response.take();
        let mut incomplete = false;
        if let Some(stream) = self.stream.take()
            && let Some(response) = &mut out
        {
            let body = self.entries.get(&stream.body).expect("sent body remains in the table");
            response["body"] = body_value(&body.bytes[body.offset..]);
            if stream.complete {
                if let Some(trailers) = body.state.get("trailers") {
                    response["trailers"] = trailers.clone();
                }
            } else {
                response["body_complete"] = json!(false);
                incomplete = true;
            }
        }
        (out, incomplete)
    }

    fn next_id(&mut self) -> u32 {
        let largest = self.entries.keys().next_back().copied().unwrap_or(0);
        if largest != u32::MAX {
            self.next = largest;
        }
        loop {
            self.next = self.next.wrapping_add(1).max(1);
            if !self.entries.contains_key(&self.next) {
                return self.next;
            }
        }
    }

    /// A new handle of `kind` with its initial state.
    pub fn create(&mut self, kind: &str, kinds: &BTreeMap<String, Kind>) -> u32 {
        let id = self.next_id();
        let state = kinds.get(kind).map(|k| k.init.clone()).filter(|v| !v.is_null()).unwrap_or_else(|| json!({}));
        self.entries.insert(id, Entry { kind: kind.to_string(), state, bytes: Vec::new(), offset: 0, open: true });
        id
    }

    /// Makes the handles in a host answer real: generated ones get fresh
    /// ids; ids a plan returned are added if the table lacks them.
    /// `outs`: (field of the ok value, or the ok value itself; kind).
    pub fn adopt(&mut self, answer: &mut Value, outs: &[(Option<String>, String)], fresh: bool, kinds: &BTreeMap<String, Kind>) {
        let Some(ok) = answer.get_mut("ok") else { return };
        for (field, kind) in outs {
            let slot = match field {
                None => Some(&mut *ok),
                Some(f) => ok.get_mut(f.as_str()),
            };
            let Some(slot) = slot else { continue };
            if fresh {
                *slot = json!(self.create(kind, kinds));
            } else if let Some(id) = slot.as_u64().and_then(|x| u32::try_from(x).ok())
                && !self.entries.contains_key(&id)
            {
                let state = kinds.get(kind).map(|k| k.init.clone()).filter(|v| !v.is_null()).unwrap_or_else(|| json!({}));
                self.entries.insert(id, Entry { kind: kind.clone(), state, bytes: Vec::new(), offset: 0, open: true });
            }
        }
    }

    /// Runs a binding. `args` are the call's named arguments; `handles` the
    /// positions of handle parameters. Returns the parts of the success value
    /// in output order, or the name of an error.
    pub fn apply(&mut self, b: &Binding, args: &[(String, Value)], handles: &[usize], ctx: &Ctx) -> Result<Vec<Value>, String> {
        let arg = |name: &str| args.iter().find(|(n, _)| n == name).map(|(_, v)| v);
        let id_at = |i: usize| args.get(i).and_then(|(_, v)| v.as_u64()).map(|x| x as u32);
        let target = match &b.handle {
            Some(p) => arg(p).and_then(Value::as_u64).map(|x| x as u32),
            None => handles.first().and_then(|i| id_at(*i)),
        };
        let field = b.field.as_deref().unwrap_or("value");
        let key = b.key.as_deref().and_then(arg).map(text).map(|k| k.to_ascii_lowercase());
        let value = match &b.value {
            Some(p) => arg(p).cloned(),
            None => args.iter().enumerate().find(|(i, (n, _))| !handles.contains(i) && Some(n.as_str()) != b.key.as_deref()).map(|(_, (_, v))| v.clone()),
        };
        match b.op {
            Op::New => Ok(vec![json!(self.create(b.kind.as_deref().unwrap_or("handle"), ctx.kinds))]),
            Op::Get => {
                let e = entry(&mut self.entries, target, ctx.bad)?;
                match e.state.get(field) {
                    None | Some(Value::Null) => Err(ctx.absent.to_string()),
                    Some(v) => Ok(vec![v.clone()]),
                }
            }
            Op::Set => {
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let v = value.unwrap_or(Value::Null);
                let v = if v.is_array() && v.as_array().is_some_and(|a| a.iter().all(Value::is_u64)) { json!(text(&v)) } else { v };
                set_field(&mut e.state, field, v);
                Ok(vec![])
            }
            Op::MapGet | Op::MapValues => {
                if self.is_streaming(target)
                    && let Some(error) = &b.stream_error
                {
                    return Err(error.clone());
                }
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let key = key.unwrap_or_default();
                let found: Vec<Value> =
                    pairs(&e.state[field]).into_iter().filter(|(k, _)| k.eq_ignore_ascii_case(&key)).map(|(_, v)| json!(text(&v))).collect();
                if b.op == Op::MapValues {
                    return Ok(vec![json!(found)]);
                }
                found.into_iter().next().map(|v| vec![v]).ok_or_else(|| ctx.absent.to_string())
            }
            Op::MapKeys => {
                if self.is_streaming(target)
                    && let Some(error) = &b.stream_error
                {
                    return Err(error.clone());
                }
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let mut keys: Vec<String> = Vec::new();
                for (k, _) in pairs(&e.state[field]) {
                    if !keys.iter().any(|x| x.eq_ignore_ascii_case(&k)) {
                        keys.push(k);
                    }
                }
                Ok(vec![json!(keys)])
            }
            Op::MapInsert | Op::MapAppend | Op::MapRemove => {
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let key = key.unwrap_or_default();
                let mut list = pairs(&e.state[field]);
                let before = list.len();
                if b.op != Op::MapAppend {
                    list.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
                }
                if b.op == Op::MapRemove && list.len() == before {
                    return Err(ctx.absent.to_string());
                }
                if b.op != Op::MapRemove {
                    list.push((key, json!(text(&value.unwrap_or(Value::Null)))));
                }
                set_field(&mut e.state, field, json!(list.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()));
                Ok(vec![])
            }
            Op::Read => {
                if self.is_streaming(target) {
                    return Err(ctx.bad.to_string());
                }
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let n = ctx.read_limit.unwrap_or(usize::MAX).min(e.bytes.len().saturating_sub(e.offset));
                let chunk = e.bytes[e.offset..e.offset + n].to_vec();
                e.offset += n;
                Ok(vec![json!(chunk)])
            }
            Op::Write => {
                let front = arg("end").is_some_and(|v| v == "front");
                if front && self.is_streaming(target) {
                    return Err(b.stream_error.as_deref().unwrap_or(ctx.bad).to_string());
                }
                let e = entry(&mut self.entries, target, ctx.bad)?;
                let data = match &value {
                    Some(Value::Array(a)) => bytes(a),
                    Some(v) => text(v).into_bytes(),
                    None => Vec::new(),
                };
                let n = data.len();
                if front {
                    e.bytes.splice(e.offset..e.offset, data);
                } else {
                    e.bytes.extend(data);
                }
                Ok(vec![json!(n)])
            }
            Op::Append => {
                let (dest, src) = (handles.first().and_then(|i| id_at(*i)), handles.get(1).and_then(|i| id_at(*i)));
                if self.is_streaming(src) {
                    return Err(ctx.bad.to_string());
                }
                let moved = {
                    let s = entry(&mut self.entries, src, ctx.bad)?;
                    s.open = false;
                    s.bytes[s.offset..].to_vec()
                };
                entry(&mut self.entries, dest, ctx.bad)?.bytes.extend(moved);
                Ok(vec![])
            }
            Op::Close | Op::Abandon => {
                entry(&mut self.entries, target, ctx.bad)?.open = false;
                if let Some(stream) = &mut self.stream
                    && Some(stream.body) == target
                {
                    stream.complete = b.op == Op::Close;
                }
                Ok(vec![])
            }
            Op::Downstream => {
                let req = ctx.request.cloned().unwrap_or_else(|| json!({}));
                let rid = self.create(b.kind.as_deref().unwrap_or("request"), ctx.kinds);
                let bid = self.create(b.body_kind.as_deref().unwrap_or("body"), ctx.kinds);
                let r = self.entries.get_mut(&rid).expect("created");
                if let (Value::Object(state), Value::Object(fields)) = (&mut r.state, &req) {
                    for (k, v) in fields.iter().filter(|(k, _)| k.as_str() != "body") {
                        state.insert(k.clone(), v.clone());
                    }
                }
                self.entries.get_mut(&bid).expect("created").bytes = text(&req["body"]).into_bytes();
                Ok(vec![json!(rid), json!(bid)])
            }
            Op::Respond => {
                let state = {
                    let response = entry(&mut self.entries, target, ctx.bad)?;
                    let state = response.state.clone();
                    if b.consume {
                        response.open = false;
                    }
                    state
                };
                let body_id = b
                    .body
                    .as_deref()
                    .and_then(arg)
                    .or_else(|| handles.get(1).and_then(|i| args.get(*i)).map(|(_, v)| v))
                    .and_then(Value::as_u64)
                    .and_then(|id| u32::try_from(id).ok());
                if self.is_streaming(body_id) {
                    return Err(ctx.bad.to_string());
                }
                let streaming = b.streaming.as_deref().and_then(arg).and_then(Value::as_u64).is_some_and(|flag| flag != 0);
                let (body, trailers) = {
                    let e = entry(&mut self.entries, body_id, ctx.bad)?;
                    if b.consume && !streaming {
                        e.open = false;
                    }
                    (body_value(&e.bytes[e.offset..]), e.state.get("trailers").cloned())
                };
                if self.response.is_some() {
                    return Err(ctx.bad.to_string());
                }
                let mut out = json!({ "status": state.get("status").cloned().unwrap_or(json!(200)), "headers": state.get("headers").cloned().unwrap_or(json!([])), "body": body });
                if streaming {
                    self.stream = Some(SentStream { body: body_id.expect("validated body"), complete: false });
                } else if let Some(trailers) = trailers {
                    out["trailers"] = trailers;
                }
                self.response = Some(out);
                Ok(vec![])
            }
        }
    }

    /// The kind of a handle, for records.
    pub fn kind(&self, id: u32) -> Option<&str> {
        self.entries.get(&id).map(|e| e.kind.as_str())
    }
}

fn body_value(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!(text),
        Err(_) => json!(bytes),
    }
}

fn entry<'a>(entries: &'a mut BTreeMap<u32, Entry>, id: Option<u32>, bad: &str) -> Result<&'a mut Entry, String> {
    id.and_then(|id| entries.get_mut(&id)).filter(|e| e.open).ok_or_else(|| bad.to_string())
}

fn set_field(state: &mut Value, field: &str, v: Value) {
    if !state.is_object() {
        *state = json!({});
    }
    state[field] = v;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(kinds: &'a BTreeMap<String, Kind>, request: Option<&'a Value>) -> Ctx<'a> {
        Ctx { kinds, request, read_limit: Some(4), bad: "badf", absent: "none" }
    }

    fn bind(op: Op) -> Binding {
        Binding {
            op,
            field: None,
            handle: None,
            key: None,
            value: None,
            kind: None,
            body_kind: None,
            body: None,
            streaming: None,
            consume: false,
            stream_error: None,
        }
    }

    #[test]
    fn adopting_the_largest_handle_does_not_alias_future_handles() {
        let mut h = Handles::default();
        let kinds = BTreeMap::new();
        let first = h.create("body", &kinds);
        let mut answer = json!({"ok":u32::MAX});
        h.adopt(&mut answer, &[(None, "body".into())], false, &kinds);
        let a = h.create("body", &kinds);
        let b = h.create("body", &kinds);
        assert_ne!(a, b);
        assert_ne!(a, first);
        assert_ne!(b, first);
        assert_ne!(a, u32::MAX);
        assert_ne!(b, u32::MAX);
        assert!(h.valid(first));
    }

    #[test]
    fn request_in_response_out() {
        let kinds: BTreeMap<String, Kind> = [("resp".to_string(), Kind { init: json!({"status": 200, "headers": []}) })].into();
        let req = json!({"method": "GET", "uri": "https://a.example/?x=1", "headers": [["X-User", "u1"]], "body": "hello world"});
        let mut h = Handles::default();
        let c = ctx(&kinds, Some(&req));
        let d = Binding { kind: Some("req".into()), body_kind: Some("body".into()), ..bind(Op::Downstream) };
        assert_eq!(h.apply(&d, &[], &[], &c).unwrap(), vec![json!(1), json!(2)]);
        let get = Binding { field: Some("uri".into()), ..bind(Op::Get) };
        assert_eq!(h.apply(&get, &[("h".into(), json!(1))], &[0], &c).unwrap(), vec![json!("https://a.example/?x=1")]);
        let hv = Binding { field: Some("headers".into()), key: Some("name".into()), ..bind(Op::MapGet) };
        let name = json!("x-user".bytes().collect::<Vec<_>>());
        assert_eq!(h.apply(&hv, &[("h".into(), json!(1)), ("name".into(), name)], &[0], &c).unwrap(), vec![json!("u1")]);
        // Reads stop at the guest's buffer.
        let read = bind(Op::Read);
        assert_eq!(h.apply(&read, &[("h".into(), json!(2))], &[0], &c).unwrap(), vec![json!(b"hell".to_vec())]);
        // A handle never given out is bad.
        assert_eq!(h.apply(&get, &[("h".into(), json!(9))], &[0], &c), Err("badf".to_string()));
        let resp = Binding { kind: Some("resp".into()), ..bind(Op::New) };
        assert_eq!(h.apply(&resp, &[], &[], &c).unwrap(), vec![json!(3)]);
        let body = Binding { kind: Some("body".into()), ..bind(Op::New) };
        assert_eq!(h.apply(&body, &[], &[], &c).unwrap(), vec![json!(4)]);
        let write = bind(Op::Write);
        h.apply(&write, &[("h".into(), json!(4)), ("buf".into(), json!(b"<p>hi</p>".to_vec())), ("end".into(), json!("back"))], &[0], &c).unwrap();
        let status = Binding { field: Some("status".into()), ..bind(Op::Set) };
        h.apply(&status, &[("h".into(), json!(3)), ("status".into(), json!(404))], &[0], &c).unwrap();
        let send = bind(Op::Respond);
        h.apply(&send, &[("h".into(), json!(3)), ("b".into(), json!(4)), ("streaming".into(), json!(0))], &[0, 1], &c).unwrap();
        assert_eq!(h.response, Some(json!({"status": 404, "headers": [], "body": "<p>hi</p>"})));
    }
}
