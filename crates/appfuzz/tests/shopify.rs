//! Shopify Functions: a `shopify.extension.toml` is enough to review one.
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const SCHEMA: &str = r#"
schema { query: Input mutation: MutationRoot }
directive @scaleLimits(rate: Float!) on FIELD_DEFINITION
directive @oneOf on INPUT_OBJECT
scalar Decimal
scalar Void
"""The input."""
type Input { cart: Cart! }
type Cart { lines: [CartLine!]! @scaleLimits(rate: 0.005) }
type CartLine { id: ID! quantity: Int! }
type MutationRoot {
  """Handles the Function result for the cart.lines.discounts.generate.run target."""
  cartLinesDiscountsGenerateRun(result: CartLinesDiscountsGenerateRunResult!): Void!
}
input CartLinesDiscountsGenerateRunResult { operations: [CartOperation!]! }
input CartOperation @oneOf { orderDiscountsAdd: OrderDiscountsAddOperation }
input OrderDiscountsAddOperation { message: String percentage: Decimal! }
"#;

const QUERY: &str = "query Input { cart { lines { id quantity } } }";

const EXTENSION: &str = r#"api_version = "2025-07"

[[extensions]]
name = "t:name"
handle = "volume-discount"
type = "function"

  [[extensions.targeting]]
  target = "cart.lines.discounts.generate.run"
  input_query = "src/run.graphql"
  export = "run"

  [extensions.build]
  command = ""
  path = "function.wasm"
"#;

/// Reads the whole input from stdin, optionally spends n² steps on its n
/// bytes, and writes `output` to stdout.
fn function(output: &str, quadratic: bool) -> Vec<u8> {
    build(output, quadratic, "")
}

/// Like `function`, but traps when the input contains `needle`.
fn trapping(output: &str, needle: &str) -> Vec<u8> {
    build(output, false, needle)
}

fn build(output: &str, quadratic: bool, needle: &str) -> Vec<u8> {
    let hex = |s: &str| -> String { s.bytes().map(|b| format!("\\{b:02x}")).collect() };
    let scan = if needle.is_empty() {
        String::new()
    } else {
        format!(
            r#"(local.set $i (i32.const 0))
        (block $notfound (loop $scan
          (br_if $notfound (i32.gt_u (i32.add (local.get $i) (i32.const {len})) (local.get $n)))
          (local.set $j (i32.const 0))
          (block $miss (loop $cmp
            (if (i32.eq (local.get $j) (i32.const {len})) (then unreachable))
            (br_if $miss (i32.ne
              (i32.load8_u (i32.add (i32.const 65536) (i32.add (local.get $i) (local.get $j))))
              (i32.load8_u (i32.add (i32.const 2048) (local.get $j)))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $cmp)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $scan)))"#,
            len = needle.len()
        )
    };
    let quad = if quadratic {
        r#"(local.set $i (i32.const 0))
        (block $oi (loop $o
          (br_if $oi (i32.ge_u (local.get $i) (local.get $n)))
          (local.set $j (i32.const 0))
          (block $ij (loop $in
            (br_if $ij (i32.ge_u (local.get $j) (local.get $n)))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $in)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $o)))"#
    } else {
        ""
    };
    let (escaped, needle) = (hex(output), hex(needle));
    let wat = format!(
        r#"(module
      (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 4)
      (data (i32.const 1024) "{escaped}")
      (data (i32.const 2048) "{needle}")
      (func (export "run") (local $n i32) (local $i i32) (local $j i32) (local $got i32)
        (block $done (loop $more
          (i32.store (i32.const 0) (i32.add (i32.const 65536) (local.get $n)))
          (i32.store (i32.const 4) (i32.const 131072))
          (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
          (local.set $got (i32.load (i32.const 8)))
          (br_if $done (i32.eqz (local.get $got)))
          (local.set $n (i32.add (local.get $n) (local.get $got)))
          (br $more)))
        {quad}
        {scan}
        (i32.store (i32.const 16) (i32.const 1024))
        (i32.store (i32.const 20) (i32.const {len}))
        (drop (call $write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))))"#,
        len = output.len()
    );
    wat::parse_str(wat).unwrap()
}

struct Fixture {
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new(wasm: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("appfuzz-shopify-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("shopify.extension.toml"), EXTENSION).unwrap();
        std::fs::write(dir.join("schema.graphql"), SCHEMA).unwrap();
        std::fs::write(dir.join("src/run.graphql"), QUERY).unwrap();
        std::fs::write(dir.join("function.wasm"), wasm).unwrap();
        Fixture { dir }
    }

    fn cli(&self, args: &[&str]) -> (i32, Value) {
        self.cli_with("shopify.extension.toml", args)
    }

    /// With another manifest in the fixture's folder.
    fn cli_with(&self, manifest: &str, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_appfuzz"))
            .args(["-j", "1", "-m"])
            .arg(self.dir.join(manifest))
            .arg("--state")
            .arg(self.dir.join("state"))
            .args(args)
            .output()
            .unwrap();
        let value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {} / {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
        (out.status.code().unwrap(), value)
    }
}

fn cart(lines: usize) -> String {
    let lines: Vec<Value> = (0..lines).map(|i| json!({"id": format!("gid://shopify/CartLine/{i}"), "quantity": 1})).collect();
    json!({"cart": {"lines": lines}}).to_string()
}

fn kinds(report: &Value) -> Vec<String> {
    report["findings"].as_array().map(|f| f.iter().map(|f| f["kind"].as_str().unwrap_or("").to_string()).collect()).unwrap_or_default()
}

const DISCOUNT: &str = r#"{"operations":[{"orderDiscountsAdd":{"message":"10% off","percentage":"10.0"}}]}"#;

#[test]
fn a_function_reads_its_cart_on_stdin_and_writes_operations() {
    let f = Fixture::new(&function(DISCOUNT, false));
    let (code, inspect) = f.cli(&["inspect"]);
    assert_eq!(code, 0, "{inspect}");
    assert_eq!(inspect["exports"][0]["key"], "run", "{inspect}");
    assert!(inspect["exports"][0]["sig"].as_str().unwrap().contains("lines: list<record { id: string, quantity: s32 }>"), "{inspect}");

    let (_, run) = f.cli(&["run", "--request", &cart(2)]);
    assert_eq!(run["outcome"]["kind"], "ok", "{run}");
    assert_eq!(run["result"], json!({"operations": [{"order-discounts-add": {"message": {"some": "10% off"}, "percentage": 10.0}}]}), "{run}");
    assert!(kinds(&run).is_empty(), "{run}");
}

#[test]
fn output_shopify_rejects_is_a_finding() {
    let f = Fixture::new(&function(r#"{"operations":[{"orderDiscountsAdd":{"percentage":"ten"}}]}"#, false));
    let (_, run) = f.cli(&["run", "--request", &cart(1)]);
    let finding = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "invalid_response").unwrap_or_else(|| panic!("{run}"));
    assert_eq!(finding["severity"], "fail");
    assert!(finding["title"].as_str().unwrap().contains("$.operations[0].orderDiscountsAdd.percentage: expected a decimal number"), "{finding}");
}

fn finding<'a>(report: &'a Value, kind: &str) -> &'a Value {
    report["findings"].as_array().and_then(|f| f.iter().find(|f| f["kind"] == kind)).unwrap_or_else(|| panic!("no {kind}: {report}"))
}

#[test]
fn instructions_are_limited_by_the_cart_size() {
    let f = Fixture::new(&function(r#"{"operations":[]}"#, true));
    let (_, small) = f.cli(&["run", "--request", &cart(3)]);
    assert!(kinds(&small).is_empty(), "{small}");
    let (_, big) = f.cli(&["run", "--request", &cart(60)]);
    let title = finding(&big, "over_budget")["title"].as_str().unwrap();
    assert!(title.ends_with("instructions on an input with 60 cart.lines, the limit for it is 11000000"), "{title}");
}

/// The lines of a request in a report.
fn lines(spec: &Value) -> usize {
    spec["args"][0]["cart"]["lines"].as_array().map_or(0, Vec::len)
}

#[test]
fn confirming_names_the_cart_size_a_slow_function_fails_at() {
    let f = Fixture::new(&function(r#"{"operations":[]}"#, true));
    let (_, big) = f.cli(&["run", "--request", &cart(60)]);
    let id = finding(&big, "over_budget")["id"].as_str().unwrap().to_string();
    let (_, confirmed) = f.cli(&["confirm", &id]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let n = lines(&confirmed["spec"]);
    let title = confirmed["finding"]["title"].as_str().unwrap();
    assert!(n > 1 && n < 60 && title.contains(&format!("on an input with {n} cart.lines")), "{title}: {confirmed}");
    // One line fewer is under the limit: n is where it starts to fail.
    let mut smaller = confirmed["spec"]["args"][0].clone();
    smaller["cart"]["lines"].as_array_mut().unwrap().remove(0);
    let (_, under) = f.cli(&["run", "--request", &smaller.to_string()]);
    assert!(!kinds(&under).contains(&"over_budget".to_string()), "{under}");
}

#[test]
fn carts_shopify_would_not_send_are_not_held_against_the_function() {
    // Reads at most 128 KiB; a bigger input overruns its buffer.
    let f = Fixture::new(&function(r#"{"operations":[]}"#, false));
    // 100 lines leave the limit at 128,000 bytes; these take 150,000.
    let huge: Vec<Value> = (0..100).map(|i| json!({"id": format!("gid://shopify/CartLine/{i}-{}", "x".repeat(1500)), "quantity": 1})).collect();
    let request = f.dir.join("huge.json");
    std::fs::write(&request, json!({"cart": {"lines": huge}}).to_string()).unwrap();
    let (_, run) = f.cli(&["run", "--request", request.to_str().unwrap()]);
    assert!(run["findings"].as_array().unwrap().iter().all(|f| f["severity"] == "info"), "{run}");
    assert!(finding(&run, "big_payload")["title"].as_str().unwrap().contains("does not run the function"), "{run}");
}

#[test]
fn a_crash_on_a_cart_shopify_never_sends_does_not_fail_the_review() {
    let f = Fixture::new(&trapping(DISCOUNT, r#""quantity":0}"#));
    let zero = json!({"cart": {"lines": [{"id": "gid://shopify/CartLine/1", "quantity": 0}]}}).to_string();
    let (_, run) = f.cli(&["run", "--request", &zero]);
    let crash = finding(&run, "crash");
    assert_eq!(crash["severity"], "info", "{run}");
    let (_, explained) = f.cli(&["show", run["run"].as_str().unwrap(), "--view", "explanation"]);
    assert!(explained.to_string().contains("cart.lines[0].quantity"), "{explained}");
    let (_, review) = f.cli(&["review", "--fresh", "--runs", "300", "--search-seed", "1"]);
    let failing: Vec<&Value> = review["findings"].as_array().unwrap().iter().filter(|x| x["severity"] != "info").collect();
    assert!(failing.is_empty(), "{review}");
}

/// A business rule of the team that owns the discount, kept next to it.
const RULES: &str = r#"
[shopify]
extension = "shopify.extension.toml"

[acceptance]
version = 1

[acceptance.checks.discounts_add_up_to_at_most_100_percent]
origin = "app"
let = { ops = "out.json.operations" }
assert = "sum(ops.map(o, o.orderDiscountsAdd.percentage)) <= 100.0"
"#;

#[test]
fn a_business_rule_reads_the_output_by_shopify_names() {
    let stacked = r#"{"operations":[{"orderDiscountsAdd":{"percentage":"60.0"}},{"orderDiscountsAdd":{"percentage":60}}]}"#;
    let f = Fixture::new(&function(stacked, false));
    std::fs::write(f.dir.join("appfuzz.toml"), RULES).unwrap();
    let (code, checked) = f.cli_with("appfuzz.toml", &["acceptance", "run"]);
    assert_eq!(code, 2, "{checked}");
    let (code, review) = f.cli_with("appfuzz.toml", &["review", "--fresh", "--runs", "50"]);
    assert_eq!(code, 2, "{review}");
    assert_eq!(finding(&review, "acceptance_failed")["severity"], "fail", "{review}");

    let f = Fixture::new(&function(DISCOUNT, false));
    std::fs::write(f.dir.join("appfuzz.toml"), RULES).unwrap();
    let (code, checked) = f.cli_with("appfuzz.toml", &["acceptance", "run"]);
    assert_eq!(code, 0, "{checked}");
}

#[test]
fn an_empty_cart_that_crashes_is_found_and_confirmed() {
    let f = Fixture::new(&trapping(DISCOUNT, r#""lines":[]"#));
    let (code, review) = f.cli(&["review", "--fresh", "--runs", "300", "--search-seed", "1"]);
    assert_eq!(code, 2, "{review}");
    let crash = finding(&review, "crash");
    assert_eq!(crash["severity"], "fail", "{review}");
    let (_, spec) = f.cli(&["show", crash["run"].as_str().unwrap(), "--field", "spec"]);
    assert_eq!(spec["args"][0]["cart"]["lines"], json!([]), "{spec}");
}
