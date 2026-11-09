//! CSP base-uri matching. The directive has no default-src fallback; each
//! serialized policy restricts independently. Keep parsing in native code so
//! page prototype changes cannot alter policy matching.
//! https://w3c.github.io/webappsec-csp/#directive-base-uri
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
    let Some(Host::Domain(host)) = url.host() else { return false };
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
