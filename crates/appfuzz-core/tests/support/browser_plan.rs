//! Browser fixture bodies are written as readable UTF-8 and encoded for the
//! private network interface's lossless byte-list wire format.
use appfuzz_core::plan::Plan;
use serde_json::Value;

pub fn parse(text: &str) -> anyhow::Result<Plan> {
    fn bodies(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key == "body" {
                        if let Some(text) = value.as_str() {
                            *value = serde_json::json!(text.as_bytes());
                        } else if let Some(inner) = value.get_mut("some") {
                            if let Some(text) = inner.as_str() {
                                *inner = serde_json::json!(text.as_bytes());
                            }
                        } else {
                            bodies(value);
                        }
                    } else {
                        bodies(value);
                    }
                }
            }
            Value::Array(values) => values.iter_mut().for_each(bodies),
            _ => {}
        }
    }
    let mut plan: Value = serde_json::from_str(text)?;
    if let Some(functions) = plan.as_object_mut() {
        for (key, value) in functions {
            if key == "appfuzz:browser/net#fetch-own" || key == "appfuzz:browser/net#fetch-other" {
                bodies(value);
            }
        }
    }
    Plan::parse(&plan.to_string())
}
