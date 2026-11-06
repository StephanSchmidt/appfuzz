//! Exact nonnegative totals: JSON numbers through u64, decimal strings above it.

use serde::{Deserialize, Deserializer, Serializer};
use serde_json::{Value, json};

pub fn json(value: u128) -> Value {
    u64::try_from(value).map_or_else(|_| Value::String(value.to_string()), |n| json!(n))
}

pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    match u64::try_from(*value) {
        Ok(n) => serializer.serialize_u64(n),
        Err(_) => serializer.serialize_str(&value.to_string()),
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Number(u64),
        Decimal(String),
    }
    match Wire::deserialize(deserializer)? {
        Wire::Number(n) => Ok(u128::from(n)),
        Wire::Decimal(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text.parse().map_err(serde::de::Error::custom),
        Wire::Decimal(_) => Err(serde::de::Error::custom("expected a nonnegative decimal integer")),
    }
}

/// Signed clock origins retain exact values outside JSON's 64-bit integers.
pub fn serialize_signed<S: Serializer>(value: &i128, serializer: S) -> Result<S::Ok, S::Error> {
    if *value >= 0 {
        return serialize(&(*value as u128), serializer);
    }
    match i64::try_from(*value) {
        Ok(n) => serializer.serialize_i64(n),
        Err(_) => serializer.serialize_str(&value.to_string()),
    }
}
