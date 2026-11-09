//! CSP base-uri matching. The directive has no default-src fallback; each
//! serialized policy restricts independently. Keep parsing in native code so
//! page prototype changes cannot alter policy matching.
//! https://w3c.github.io/webappsec-csp/#directive-base-uri
use base64::{
    Engine as _, alphabet,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use url::{Host, Url};

fn whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{c}' | '\r' | ' ')
}

pub(crate) fn allows_base(policy: &str, candidate: &str, document: &str) -> bool {
    let (Ok(url), Ok(origin)) = (Url::parse(candidate), Url::parse(document)) else { return false };
    policy.split(',').all(|policy| {
        for directive in policy.split(';') {
            let mut words = directive.split(whitespace).filter(|s| !s.is_empty());
            if words.next().is_some_and(|name| name.eq_ignore_ascii_case("base-uri")) {
                return words.any(|expression| matches_source(expression, &url, &origin));
            }
        }
        true
    })
}

// Resolve directive fallbacks before inspecting a source list. The first
// duplicate wins, including when its value is empty.
fn directive<'a>(policy: &'a str, requested: &str) -> Option<Vec<&'a str>> {
    let names: &[&str] = match requested {
        "script-src-elem" => &["script-src-elem", "script-src", "default-src"],
        "script-src-attr" => &["script-src-attr", "script-src", "default-src"],
        "style-src-elem" => &["style-src-elem", "style-src", "default-src"],
        "style-src-attr" => &["style-src-attr", "style-src", "default-src"],
        "worker-src" => &["worker-src", "child-src", "script-src", "default-src"],
        "frame-src" => &["frame-src", "child-src", "default-src"],
        "base-uri" | "form-action" => &[requested],
        _ => &[requested, "default-src"],
    };
    for name in names {
        for serialized in policy.split(';') {
            let mut words = serialized.split(whitespace).filter(|v| !v.is_empty());
            if words.next().is_some_and(|value| value.eq_ignore_ascii_case(name)) {
                return Some(words.collect());
            }
        }
    }
    None
}
fn keyword(list: &[&str], word: &str) -> bool {
    list.iter().any(|v| v.eq_ignore_ascii_case(word))
}
fn base64_value(value: &str) -> bool {
    let unpadded = value.trim_end_matches('=');
    !unpadded.is_empty() && value.len() - unpadded.len() <= 2 && unpadded.bytes().all(|v| v.is_ascii_alphanumeric() || matches!(v, b'+' | b'/' | b'-' | b'_'))
}
fn nonce(expression: &str) -> Option<&str> {
    let value = expression.strip_prefix('\'')?.strip_suffix('\'')?;
    (value.get(..6)?.eq_ignore_ascii_case("nonce-") && base64_value(&value[6..])).then_some(&value[6..])
}
fn hash_source(expression: &str) -> Option<(&str, &str)> {
    let value = expression.strip_prefix('\'')?.strip_suffix('\'')?;
    let (algorithm, value) = value.split_once('-')?;
    (matches!(algorithm.to_ascii_lowercase().as_str(), "sha256" | "sha384" | "sha512") && base64_value(value)).then_some((algorithm, value))
}
fn decoded_hash(value: &str) -> Option<Vec<u8>> {
    let normalized = value.replace('-', "+").replace('_', "/");
    GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent))
        .decode(normalized)
        .ok()
}
fn digest_matches(algorithm: &str, value: &str, source: &str) -> bool {
    let actual = match algorithm.to_ascii_lowercase().as_str() {
        "sha256" => base64::engine::general_purpose::STANDARD.encode(Sha256::digest(source.as_bytes())),
        "sha384" => base64::engine::general_purpose::STANDARD.encode(Sha384::digest(source.as_bytes())),
        "sha512" => base64::engine::general_purpose::STANDARD.encode(Sha512::digest(source.as_bytes())),
        _ => return false,
    };
    actual == value.replace('-', "+").replace('_', "/")
}
fn inline_allowed(list: &[&str], nonce_value: &str, source: &str, attribute: bool, script: bool, parser: bool) -> bool {
    let protected = list.iter().any(|v| nonce(v).is_some() || hash_source(v).is_some()) || (script && keyword(list, "'strict-dynamic'"));
    if !protected && keyword(list, "'unsafe-inline'") {
        return true;
    }
    if !attribute && !nonce_value.is_empty() && list.iter().any(|v| nonce(v) == Some(nonce_value)) {
        return true;
    }
    if script && !attribute && !parser && keyword(list, "'strict-dynamic'") {
        return true;
    }
    (!attribute || keyword(list, "'unsafe-hashes'"))
        && list.iter().any(|v| hash_source(v).is_some_and(|(algorithm, value)| digest_matches(algorithm, value, source)))
}
fn integrity_allowed(list: &[&str], metadata: &str) -> bool {
    let recognized: Vec<_> = metadata
        .split(whitespace)
        .filter_map(|v| {
            let value = v.split('?').next()?;
            let (algorithm, hash) = value.split_once('-')?;
            let quoted = format!("'{algorithm}-{hash}'");
            hash_source(&quoted).is_some().then_some((algorithm, hash))
        })
        .collect();
    !recognized.is_empty()
        && recognized.iter().all(|(algorithm, hash)| {
            list.iter().any(|v| {
                hash_source(v).is_some_and(|(candidate, value)| {
                    candidate.eq_ignore_ascii_case(algorithm) && decoded_hash(value).is_some_and(|v| Some(v) == decoded_hash(hash))
                })
            })
        })
}
pub(crate) fn integrity_matches(metadata: &str, source: &[u8]) -> bool {
    let candidates: Vec<_> = metadata
        .split(whitespace)
        .filter_map(|token| {
            let token = token.split('?').next()?;
            let (algorithm, value) = token.split_once('-')?;
            let strength = match algorithm.to_ascii_lowercase().as_str() {
                "sha256" => 256,
                "sha384" => 384,
                "sha512" => 512,
                _ => return None,
            };
            base64_value(value).then_some((strength, value))
        })
        .collect();
    let Some(strength) = candidates.iter().map(|v| v.0).max() else { return true };
    let actual = match strength {
        256 => Sha256::digest(source).to_vec(),
        384 => Sha384::digest(source).to_vec(),
        _ => Sha512::digest(source).to_vec(),
    };
    candidates.iter().any(|(bits, value)| *bits == strength && decoded_hash(value).is_some_and(|expected| expected == actual))
}
fn requested(kind: &str) -> &str {
    match kind {
        "inline" | "script" => "script-src-elem",
        "handler" => "script-src-attr",
        "eval" | "wasm" => "script-src",
        "connect" => "connect-src",
        "base" => "base-uri",
        "form" => "form-action",
        "image" => "img-src",
        "frame" => "frame-src",
        "worker" => "worker-src",
        "style-inline" | "style" => "style-src-elem",
        "style-attr" => "style-src-attr",
        _ => kind,
    }
}
fn allowed(list: &[&str], kind: &str, candidate: &str, origin: &Url, nonce_value: &str, source: &str, parser: bool) -> bool {
    match kind {
        "eval" => keyword(list, "'unsafe-eval'"),
        "wasm" => keyword(list, "'unsafe-eval'") || keyword(list, "'wasm-unsafe-eval'"),
        "inline" | "handler" | "style-inline" | "style-attr" => {
            inline_allowed(list, nonce_value, source, matches!(kind, "handler" | "style-attr"), matches!(kind, "inline" | "handler"), parser)
        }
        _ => {
            if kind == "script" {
                if !nonce_value.is_empty() && list.iter().any(|v| nonce(v) == Some(nonce_value)) || integrity_allowed(list, source) {
                    return true;
                }
                if keyword(list, "'strict-dynamic'") {
                    return !parser;
                }
            }
            Url::parse(candidate).is_ok_and(|url| list.iter().any(|expression| matches_source(expression, &url, origin)))
        }
    }
}
/// Returns all enforcing-policy decisions as private tuples. Keeping the
/// serialized policy per violation preserves policy intersection and reporting.
pub(crate) fn check(policy: &str, kind: &str, candidate: &str, origin: &str, nonce_value: &str, source: &str, parser: bool) -> String {
    let Ok(origin) = Url::parse(origin) else { return "[]".to_owned() };
    let mut violations = Vec::new();
    for policy in policy.split(',') {
        let policy = policy.trim_matches(whitespace);
        let name = requested(kind);
        let Some(list) = directive(policy, name) else { continue };
        if !allowed(&list, kind, candidate, &origin, nonce_value, source, parser) {
            let blocked = match kind {
                "inline" | "handler" | "style-inline" | "style-attr" => "inline".to_owned(),
                "eval" => "eval".to_owned(),
                "wasm" => "wasm-eval".to_owned(),
                _ => blocked_uri(candidate, &origin),
            };
            let sample = if keyword(&list, "'report-sample'") { source.chars().take(40).collect::<String>() } else { String::new() };
            violations.push(vec![policy.to_owned(), name.to_owned(), blocked, sample]);
        }
    }
    serde_json::to_string(&violations).unwrap_or_else(|_| "[]".to_owned())
}
fn blocked_uri(candidate: &str, origin: &Url) -> String {
    let Ok(mut url) = Url::parse(candidate) else { return candidate.to_owned() };
    if !matches!(url.scheme(), "http" | "https") {
        return url.scheme().to_owned();
    }
    if url.origin() != origin.origin() {
        return url.origin().ascii_serialization();
    }
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

fn scheme_matches(pattern: &str, scheme: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    pattern == scheme || matches!((pattern.as_str(), scheme), ("http", "https") | ("ws", "wss" | "http" | "https") | ("wss", "https"))
}

fn valid_scheme(scheme: &str) -> bool {
    scheme.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) && scheme.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

fn matches_source(expression: &str, url: &Url, origin: &Url) -> bool {
    if expression == "*" {
        return matches!(url.scheme(), "http" | "https") || url.scheme() == origin.scheme();
    }
    if expression.eq_ignore_ascii_case("'self'") {
        if url.scheme() == "blob" || !origin.origin().is_tuple() {
            return false;
        }
        return url.origin() == origin.origin()
            || (url.host() == origin.host()
                && (url.port_or_known_default() == origin.port_or_known_default() || (url.port().is_none() && origin.port().is_none()))
                && (matches!(url.scheme(), "https" | "wss") || (origin.scheme() == "http" && matches!(url.scheme(), "http" | "ws"))));
    }
    if let Some(scheme) = expression.strip_suffix(':') {
        return valid_scheme(scheme) && scheme_matches(scheme, url.scheme());
    }
    let (scheme, rest) = expression.split_once("://").unwrap_or((origin.scheme(), expression));
    if !valid_scheme(scheme) || !scheme_matches(scheme, url.scheme()) {
        return false;
    }
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(host, _)| (host, &rest[host.len()..]));
    let (pattern, port) = authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
    let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
    if pattern != "*"
        && (domain.is_empty()
            || !domain.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.'))
            || domain.starts_with('.')
            || domain.contains(".."))
    {
        return false;
    }
    let host_storage;
    let host = match url.host() {
        Some(Host::Domain(host)) => host,
        Some(Host::Ipv4(ip)) if ip.is_loopback() && ip.octets() == [127, 0, 0, 1] => {
            host_storage = ip.to_string();
            host_storage.as_str()
        }
        _ => return false,
    };
    let lower = pattern.to_ascii_lowercase();
    if lower != "*" && !if let Some(suffix) = lower.strip_prefix('*') { host.ends_with(suffix) } else { host == lower } {
        return false;
    }
    if let Some(port) = port {
        if port != "*" && (port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) || port.parse::<u16>().ok() != url.port_or_known_default()) {
            return false;
        }
    } else if url.port().is_some() {
        return false;
    }
    // host-source's path-absolute grammar excludes queries, fragments,
    // backslashes, raw non-ASCII and control characters.
    if !path.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'/' | b'%' | b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@')
    }) {
        return false;
    }
    path_matches(path, url.path())
}

fn decode(piece: &str) -> Vec<u8> {
    let bytes = piece.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |c: u8| (c as char).to_digit(16).map(|n| n as u8);
            if let (Some(a), Some(b)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                result.push(a * 16 + b);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    result
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() || (pattern == "/" && path.is_empty()) {
        return true;
    }
    let prefix = pattern.ends_with('/');
    let mut actual = path.split('/');
    let pattern = if prefix { &pattern[..pattern.len() - 1] } else { pattern };
    for piece in pattern.split('/') {
        if actual.next().is_none_or(|candidate| decode(piece) != decode(candidate)) {
            return false;
        }
    }
    prefix || actual.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::allows_base;
    const PAGE: &str = "https://app.example/path";
    #[test]
    fn engine_compilation_observer_preserves_direct_eval_scope() {
        let rt = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&rt).unwrap();
        context.with(|ctx| {
            crate::web::install(&ctx).unwrap();
            let ok: bool = ctx
                .eval(
                    r#"
                let observations=[];
                __native.setStringCompilationHook((source,kind,body)=>observations.push([source,kind,body]));
                function test(){let lexical=23;const read=eval('lexical');eval('lexical=31');return read===23&&lexical===31}
                test()&&observations.length===2&&observations[0][0]==='lexical'&&observations[0][1]===0
            "#,
                )
                .unwrap();
            assert!(ok);
        });
    }
    #[test]
    fn engine_observer_covers_function_families_after_single_ordered_conversion() {
        let rt = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&rt).unwrap();
        context.with(|ctx| {
            crate::web::install(&ctx).unwrap();
            let ok: bool = ctx
                .eval(
                    r#"
                let converted=[],observed=[];
                __native.setStringCompilationHook((source,kind,body)=>observed.push([kind,body]));
                Function({toString(){converted.push('parameter');return 'a'}},{toString(){converted.push('body');return 'return a'}});
                (function*(){}).constructor('yield 1');(async function(){}).constructor('return 1');(async function*(){}).constructor('yield 1');
                converted.join(',')==='parameter,body'&&JSON.stringify(observed)===JSON.stringify([[1,'return a'],[2,'yield 1'],[3,'return 1'],[4,'yield 1']])
            "#,
                )
                .unwrap();
            assert!(ok);
        });
    }
    #[test]
    fn engine_observer_is_rooted_and_denies_before_execution_or_constructor_prototype_access() {
        let rt = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&rt).unwrap();
        context.with(|ctx| {
            crate::web::install(&ctx).unwrap();
            ctx.eval::<(), _>(r#"globalThis.marker=0;__native.setStringCompilationHook(()=>{throw new EvalError('blocked')});delete globalThis.__native"#)
                .unwrap();
        });
        rt.run_gc();
        context.with(|ctx| {
            let ok: bool = ctx
                .eval(
                    r#"
                let reads=0,errors=0;const target=new Proxy(function(){},{get(t,key){if(key==='prototype')reads++;return Reflect.get(t,key)}});
                try{eval('marker=1')}catch(e){if(e instanceof EvalError)errors++}
                try{Reflect.construct(Function,['return 1'],target)}catch(e){if(e instanceof EvalError)errors++}
                const value={};eval(value)===value&&marker===0&&reads===0&&errors===2
            "#,
                )
                .unwrap();
            assert!(ok);
        });
    }
    #[test]
    fn private_compilation_keeps_engine_strings_and_does_not_reenter_eval_observer() {
        let rt = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&rt).unwrap();
        context.with(|ctx| {
            crate::web::install(&ctx).unwrap();
            let ok: bool = ctx
                .eval(
                    r#"
                let seen=0;__native.setStringCompilationHook(()=>{seen++;throw new EvalError('blocked')});
                const source="globalThis.surrogate='"+String.fromCharCode(0xd800)+"';globalThis.nul='"+String.fromCharCode(0)+"'";
                const run=__native.compileClassicScript(source,'timer.js');run();
                seen===0&&surrogate.charCodeAt(0)===0xd800&&nul.charCodeAt(0)===0
            "#,
                )
                .unwrap();
            assert!(ok);
        });
    }
    fn decision(policy: &str, kind: &str, url: &str, nonce: &str, source: &str, parser: bool) -> serde_json::Value {
        serde_json::from_str(&super::check(policy, kind, url, PAGE, nonce, source, parser)).unwrap()
    }
    #[test]
    fn runtime_directives_fall_back_independently_and_intersect() {
        for (policy, kind, expected) in [
            ("default-src 'none'", "connect", false),
            ("default-src 'none';connect-src 'self'", "connect", true),
            ("script-src 'none';script-src-elem 'unsafe-inline'", "inline", true),
            ("script-src 'none';script-src-attr 'unsafe-inline'", "inline", false),
            ("script-src-elem 'none'", "eval", true),
            ("script-src 'unsafe-eval'", "eval", true),
            ("default-src 'none'", "eval", false),
            ("base-uri 'none'", "inline", true),
            ("script-src 'unsafe-inline';script-src 'none'", "inline", true),
        ] {
            assert_eq!(decision(policy, kind, PAGE, "", "x", false).as_array().unwrap().is_empty(), expected, "{policy} {kind}");
        }
        let value = decision("script-src 'none', default-src 'none'", "inline", "", "", "x", false);
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert_eq!(value[0][1], "script-src-elem");
        assert_eq!(value[1][1], "script-src-elem");
    }
    #[test]
    fn nonce_matching_is_exact_and_handlers_do_not_inherit_nonces() {
        for (policy, kind, nonce, expected) in [
            ("script-src 'nonce-abCD'", "inline", "abCD", true),
            ("script-src 'nonce-abCD'", "inline", "ABCD", false),
            ("script-src 'unsafe-inline' 'nonce-abCD'", "inline", "", false),
            ("script-src 'unsafe-inline' 'nonce-?'", "inline", "", true),
            ("script-src 'nonce-abCD'", "handler", "abCD", false),
            ("script-src 'nonce-abCD'", "script", "abCD", true),
        ] {
            assert_eq!(decision(policy, kind, "https://other.example/file.js", nonce, "x", false).as_array().unwrap().is_empty(), expected, "{policy} {kind}");
        }
    }
    #[test]
    fn strict_dynamic_distinguishes_parser_inserted_scripts_and_handlers() {
        for kind in ["inline", "script"] {
            for parser in [true, false] {
                assert_eq!(decision("script-src 'strict-dynamic'", kind, PAGE, "", "x", parser).as_array().unwrap().is_empty(), !parser, "{kind} {parser}");
            }
        }
        assert!(!decision("script-src 'strict-dynamic' 'unsafe-inline'", "handler", "", "", "x", false).as_array().unwrap().is_empty());
    }
    #[test]
    fn hashes_compare_encoded_values_and_attribute_hashes_require_opt_in() {
        use base64::Engine as _;
        use sha2::Digest;
        let source = "globalThis.cspHit=true";
        let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(source));
        let policy = format!("script-src 'sha256-{hash}'");
        assert!(decision(&policy, "inline", "", "", source, true).as_array().unwrap().is_empty());
        assert!(!decision(&policy, "handler", "", "", source, false).as_array().unwrap().is_empty());
        assert!(decision(&format!("{policy} 'unsafe-hashes'"), "handler", "", "", source, false).as_array().unwrap().is_empty());
        assert!(!decision(&format!("script-src 'sha256-{}'", hash.trim_end_matches('=')), "inline", "", "", source, false).as_array().unwrap().is_empty());
        assert!(
            decision(&format!("script-src 'sha256-{}'", hash.replace('+', "-").replace('/', "_")), "inline", "", "", source, false)
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn integrity_checks_use_the_strongest_recognized_digest_and_actual_bytes() {
        use base64::Engine as _;
        use sha2::Digest;
        let bytes = b"script";
        let good = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes));
        assert!(super::integrity_matches(&format!("sha256-{good}"), bytes));
        assert!(!super::integrity_matches(&format!("sha256-{good}"), b"changed"));
        assert!(!super::integrity_matches(&format!("sha256-{good} sha512-AAAA"), bytes));
        assert!(super::integrity_matches("unknown-AAAA", bytes));
    }
    #[test]
    fn violation_records_strip_cross_origin_paths_and_bound_samples() {
        let row = decision("connect-src 'none'", "connect", "https://other.example/private?secret=x#f", "", "", false);
        assert_eq!(row[0][2], "https://other.example");
        let row = decision("connect-src 'none'", "connect", "https://app.example/private?q=x#f", "", "", false);
        assert_eq!(row[0][2], "https://app.example/private?q=x");
        let row = decision("script-src 'report-sample'", "inline", "", "", &"x".repeat(100), false);
        assert_eq!(row[0][3], "x".repeat(40));
        assert!(super::allows_base("base-uri http://127.0.0.1:8080", "http://127.0.0.1:8080/a", PAGE));
        assert!(!super::allows_base("base-uri http://127.0.0.2:8080", "http://127.0.0.2:8080/a", PAGE));
    }
    #[test]
    fn policies_intersect_and_the_first_duplicate_directive_wins() {
        for policy in ["base-uri 'none'", "base-uri", "base-uri *, base-uri 'none'", "BASE-URI 'NONE';base-uri *"] {
            assert!(!allows_base(policy, PAGE, PAGE), "{policy}");
        }
        for policy in ["", "default-src 'none'", "base-uri *;base-uri 'none'", "base-uri 'none' 'SELF'", "script-src 'none', base-uri 'self'"] {
            assert!(allows_base(policy, PAGE, PAGE), "{policy}");
        }
    }
    #[test]
    fn source_hosts_ports_and_scheme_upgrades() {
        for (source, candidate, expected) in [
            ("'self'", PAGE, true),
            ("'self'", "https://other.example/", false),
            ("https:", "http://app.example/", false),
            ("http:", PAGE, true),
            ("https://*.other.example", "https://sub.other.example/", true),
            ("https://*.other.example", "https://other.example/", false),
            ("https://other.example:443", "https://other.example/", true),
            ("https://other.example", "https://other.example:8443/", false),
            ("https://other.example:*", "https://other.example:8443/", true),
            ("http://other.example", "https://other.example/", true),
            ("other.example", "http://other.example/", false),
            ("HTTPS://OTHER.EXAMPLE", "https://other.example/", true),
            ("https://other.example.evil", "https://other.example/", false),
            ("'nonce-x'", PAGE, false),
            ("*", "blob:https://app.example/123", false),
            ("'self'", "blob:https://app.example/123", false),
            ("'self'", "https://app.example:8443/", false),
        ] {
            assert_eq!(allows_base(&format!("base-uri {source}"), candidate, PAGE), expected, "{source} {candidate}");
        }
        assert!(allows_base("base-uri 'self'", "https://app.example/", "http://app.example/"));
        assert!(!allows_base("base-uri 'self'", "http://app.example/", "https://app.example/"));
    }
    #[test]
    fn paths_compare_decoded_segments_without_folding_case() {
        for (path, candidate, expected) in [
            ("/Allowed/", "/Allowed/child", true),
            ("/Allowed/", "/allowed/child", false),
            ("/Al%6cowed/", "/Allowed/child", true),
            ("/Allowed", "/Allowed/child", false),
            ("/Allowed", "/Allowed", true),
            ("/a%2fb/", "/a/b/", false),
            ("/a%2fb/", "/a%2Fb/child", true),
            ("/Allowed/", "/AllowedElsewhere/", false),
        ] {
            assert_eq!(
                allows_base(&format!("base-uri https://other.example{path}"), &format!("https://other.example{candidate}"), PAGE),
                expected,
                "{path} {candidate}"
            );
        }
    }
}
