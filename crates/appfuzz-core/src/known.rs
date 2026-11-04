//! What appfuzz knows about well-known host APIs without a manifest: Spin's
//! SQL, key-value, Redis and MQTT, and `wasi:keyvalue`. Their WIT says what
//! a call does (a SQL statement, a write, a message sent), so these labels
//! are facts, not guesses. A manifest section for the same function keeps
//! what it sets; only fields it leaves empty are filled in.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::manifest::{FunctionSpec, Manifest};
use crate::wit::Interface;

const KNOWN: &str = r#"
# Spin 2/3 (fermyon:spin@2.0.0) and the Spin 3 packages.
["fermyon:spin/sqlite#[method]connection.execute"]
params = { statement = "sql" }
["spin:sqlite/sqlite#[method]connection.execute"]
params = { statement = "sql" }
["fermyon:spin/postgres#[method]connection.query"]
params = { statement = "sql" }
["fermyon:spin/postgres#[method]connection.execute"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.query"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.execute"]
params = { statement = "sql" }
["fermyon:spin/mysql#[method]connection.query"]
params = { statement = "sql" }
["fermyon:spin/mysql#[method]connection.execute"]
params = { statement = "sql" }

["fermyon:spin/key-value#[method]store.set"]
effect = "write"
idempotent = true
["fermyon:spin/key-value#[method]store.delete"]
effect = "delete"
idempotent = true

["fermyon:spin/redis#[method]connection.publish"]
effect = "external"
["fermyon:spin/redis#[method]connection.set"]
effect = "write"
idempotent = true
["fermyon:spin/redis#[method]connection.incr"]
effect = "write"
["fermyon:spin/redis#[method]connection.sadd"]
effect = "write"
idempotent = true
["fermyon:spin/redis#[method]connection.del"]
effect = "delete"
idempotent = true
["fermyon:spin/redis#[method]connection.srem"]
effect = "delete"
idempotent = true

["fermyon:spin/mqtt#[static]connection.open"]
params = { password = "secret" }
["fermyon:spin/mqtt#[method]connection.publish"]
effect = "external"

# wasi:keyvalue 0.2 drafts (Spin 3, wasmCloud).
["wasi:keyvalue/store#[method]bucket.set"]
effect = "write"
idempotent = true
["wasi:keyvalue/store#[method]bucket.delete"]
effect = "delete"
idempotent = true
["wasi:keyvalue/atomics#increment"]
effect = "write"
["wasi:keyvalue/batch#get-many"]
batch_of = "wasi:keyvalue/store#[method]bucket.get"
["wasi:keyvalue/batch#set-many"]
effect = "write"
idempotent = true
batch_of = "wasi:keyvalue/store#[method]bucket.set"
["wasi:keyvalue/batch#delete-many"]
effect = "delete"
idempotent = true
batch_of = "wasi:keyvalue/store#[method]bucket.delete"
"#;

/// Fills in the labels of known host functions the component imports.
pub fn defaults(manifest: &mut Manifest, imports: &[Interface]) -> Result<()> {
    let known: BTreeMap<String, FunctionSpec> = toml::from_str(KNOWN).context("built-in host API labels")?;
    for f in imports.iter().flat_map(|i| &i.funcs) {
        let Some(k) = known.get(&f.key) else { continue };
        let key = manifest
            .functions
            .keys()
            .find(|m| {
                let (i, n) = m.split_once('#').unwrap_or(("", m));
                crate::manifest::fn_key(i, n) == f.key
            })
            .cloned()
            .unwrap_or_else(|| f.key.clone());
        let spec = manifest.functions.entry(key).or_default();
        for (p, l) in &k.params {
            spec.params.entry(p.clone()).or_insert(*l);
        }
        if spec.effect.is_none() && k.effect.is_some() {
            spec.effect = k.effect;
            spec.idempotent |= k.idempotent;
        }
        if spec.batch_of.is_none() {
            spec.batch_of.clone_from(&k.batch_of);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_parses() {
        let known: BTreeMap<String, FunctionSpec> = toml::from_str(KNOWN).unwrap();
        assert!(known["fermyon:spin/sqlite#[method]connection.execute"].params.contains_key("statement"));
    }
}
