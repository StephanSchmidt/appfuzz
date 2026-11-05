//! Content-Security-Policy: what scripts in the app's markup may load and
//! where they may send data. Under `html:scripts` the policy has to keep
//! them on the app's origin and on the granted hosts.

use std::collections::BTreeMap;

use crate::detect::Severity;

/// Fetch directives the policy must limit, and what each falls back to.
const FETCH: &[(&str, &[&str])] = &[
    ("script-src", &["default-src"]),
    ("connect-src", &["default-src"]),
    ("img-src", &["default-src"]),
    ("media-src", &["default-src"]),
    ("font-src", &["default-src"]),
    ("style-src", &["default-src"]),
    ("frame-src", &["child-src", "default-src"]),
    ("worker-src", &["child-src", "script-src", "default-src"]),
    ("manifest-src", &["default-src"]),
    ("object-src", &["default-src"]),
];

/// Directives without a fallback that must be set.
const NAVIGATION: &[&str] = &["form-action", "base-uri"];

/// One policy: directive → its sources, lowercased. The first of a
/// repeated directive counts, as in a browser.
type Policy = BTreeMap<String, Vec<String>>;

/// The policies in header values or meta contents: a comma separates
/// policies, a semicolon directives.
fn parse(texts: &[&str]) -> Vec<Policy> {
    let mut out = Vec::new();
    for p in texts.iter().flat_map(|t| t.split(',')) {
        let mut policy = Policy::new();
        for d in p.split(';') {
            let mut words = d.split_ascii_whitespace();
            let Some(name) = words.next() else { continue };
            policy.entry(name.to_ascii_lowercase()).or_insert_with(|| words.map(str::to_ascii_lowercase).collect());
        }
        if !policy.is_empty() {
            out.push(policy);
        }
    }
    out
}

/// What is wrong with a source list for `dir`, given the granted hosts.
fn problems(dir: &str, list: Option<&Vec<String>>, hosts: &[String]) -> Vec<String> {
    let Some(list) = list else { return vec![format!("leaves {dir} open (no {dir} and no default-src)")] };
    let mut out = Vec::new();
    let passive = matches!(dir, "img-src" | "font-src" | "media-src");
    for s in list {
        if s.starts_with('\'') {
            if dir == "script-src" && s == "'strict-dynamic'" {
                out.push(format!("lets scripts in script-src load scripts from anywhere ({s})"));
            }
            continue;
        }
        if s == "*" {
            out.push(format!("allows any host in {dir} (*)"));
            continue;
        }
        if let Some(scheme) = s.strip_suffix(':') {
            if !(passive && matches!(scheme, "data" | "blob" | "mediastream")) {
                out.push(format!("allows any {s} URL in {dir}"));
            }
            continue;
        }
        let rest = s.split_once("://").map_or(s.as_str(), |(_, r)| r);
        let host = rest.split(['/', ':']).next().unwrap_or(rest);
        if host == "*" {
            out.push(format!("allows any host in {dir} ({s})"));
        } else if !crate::dest::granted(host.trim_start_matches("*."), hosts) {
            out.push(format!("allows {s} in {dir}, a host the grants don't list"));
        }
    }
    out
}

/// What is wrong with the policies that apply together (each one limits,
/// so a directive is limited when some policy limits it): (severity, what).
/// No policy at all is a fail.
pub(crate) fn weaknesses(texts: &[&str], hosts: &[String]) -> Vec<(Severity, String)> {
    let policies = parse(texts);
    if policies.is_empty() {
        return vec![(Severity::Fail, "has no Content-Security-Policy".into())];
    }
    let mut out = Vec::new();
    let mut need = |dir: &str, list: &dyn Fn(&Policy) -> Option<&Vec<String>>| {
        let each: Vec<Vec<String>> = policies.iter().map(|p| problems(dir, list(p), hosts)).collect();
        if each.iter().all(|p| !p.is_empty()) {
            let fewest = each.into_iter().min_by_key(Vec::len).unwrap_or_default();
            out.extend(fewest.into_iter().map(|w| (Severity::Fail, w)));
        }
    };
    for (dir, fallback) in FETCH {
        need(dir, &|p: &Policy| p.get(*dir).or_else(|| fallback.iter().find_map(|f| p.get(*f))));
    }
    for dir in NAVIGATION {
        need(dir, &|p: &Policy| p.get(*dir));
    }
    // Eval runs when every policy allows it.
    let eval = |p: &Policy| p.get("script-src").or_else(|| p.get("default-src")).is_some_and(|l| l.iter().any(|s| s == "'unsafe-eval'"));
    if policies.iter().all(eval) {
        out.push((Severity::Warn, "allows 'unsafe-eval' in script-src: scripts may run text as code".into()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.example; img-src 'self' data:; form-action 'self'; base-uri 'none'";

    fn weak(texts: &[&str]) -> Vec<String> {
        weaknesses(texts, &["cdn.example".into(), "api.example".into()]).into_iter().map(|(s, w)| format!("{s:?}: {w}")).collect()
    }

    #[test]
    fn a_good_policy_passes() {
        assert_eq!(weak(&[GOOD]), Vec::<String>::new());
        assert_eq!(weak(&["default-src 'self' https://api.example:443/v1/ *.cdn.example; form-action 'none'; base-uri 'self'"]), Vec::<String>::new());
    }

    #[test]
    fn finds_what_is_open() {
        assert_eq!(weak(&[]), ["Fail: has no Content-Security-Policy"]);
        assert_eq!(weak(&["script-src 'self'"]).len(), 10, "{:?}", weak(&["script-src 'self'"]));
        let w = weak(&["default-src 'self' https: evil.example *; form-action 'self'; base-uri 'self'"]);
        assert!(w.iter().any(|w| w.contains("any https: URL in script-src")), "{w:?}");
        assert!(w.iter().any(|w| w.contains("evil.example in connect-src, a host the grants don't list")), "{w:?}");
        assert!(w.iter().any(|w| w.contains("any host in img-src (*)")), "{w:?}");
        // data: runs code in a script or a frame, not in an image.
        let w = weak(&["default-src 'self' data:; form-action 'self'; base-uri 'self'"]);
        assert!(w.iter().any(|w| w.contains("data: URL in script-src")) && !w.iter().any(|w| w.contains("img-src")), "{w:?}");
        let w = weak(&["default-src 'self'; script-src 'self' 'strict-dynamic' 'unsafe-eval'; form-action 'self'; base-uri 'self'"]);
        assert_eq!(
            w,
            [
                "Fail: lets scripts in script-src load scripts from anywhere ('strict-dynamic')",
                "Warn: allows 'unsafe-eval' in script-src: scripts may run text as code"
            ]
        );
    }

    #[test]
    fn policies_add_up() {
        // The header leaves form-action open; the platform's policy closes it.
        let header = "default-src 'self'; base-uri 'self'";
        assert_eq!(weak(&[header]), ["Fail: leaves form-action open (no form-action and no default-src)"]);
        assert_eq!(weak(&[header, "form-action 'self'"]), Vec::<String>::new());
        assert_eq!(weak(&[&format!("{header}, form-action 'self'")]), Vec::<String>::new());
        // Eval runs only if every policy allows it.
        let eval = "default-src 'self' 'unsafe-eval'; form-action 'self'; base-uri 'self'";
        assert_eq!(weak(&[eval]).len(), 1);
        assert_eq!(weak(&[eval, "script-src 'self'"]), Vec::<String>::new());
    }
}
