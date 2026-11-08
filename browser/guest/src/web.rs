//! `globalThis.__native`: the Web APIs the shim takes from Rust, where a
//! browser's behaviour is a parser appfuzz-core already uses: URLs by the
//! WHATWG rules (the `url` crate, which judges where requests go), so a
//! page's own checks (`new URL(next).host === location.host`) parse as in
//! a browser.

use rquickjs::convert::List;
use rquickjs::{Ctx, Function, Object, Result, Value};
use url::{Url, form_urlencoded, quirks};

pub fn install(ctx: &Ctx<'_>) -> Result<()> {
    let n = Object::new(ctx.clone())?;
    n.set("url", Function::new(ctx.clone(), url_parse_js)?)?;
    n.set("urlSet", Function::new(ctx.clone(), url_set_js)?)?;
    n.set("formParse", Function::new(ctx.clone(), form_parse_js)?)?;
    n.set("formSerialize", Function::new(ctx.clone(), form_serialize)?)?;
    n.set("cookieDomainMatches", Function::new(ctx.clone(), cookie_domain_matches)?)?;
    n.set("cookiePublicSuffix", Function::new(ctx.clone(), cookie_public_suffix)?)?;
    n.set("cookieSite", Function::new(ctx.clone(), cookie_site)?)?;
    n.set("bidiDirection", Function::new(ctx.clone(), bidi_direction)?)?;
    n.set("inputColor", Function::new(ctx.clone(), input_color)?)?;
    ctx.globals().set("__native", n)
}

// The native JSON parser defines own data properties. rquickjs's ordinary
// Vec/List conversion uses assignment and can invoke page prototype setters.
pub(crate) fn private_json<'js>(ctx: &Ctx<'js>, value: serde_json::Value) -> Result<Value<'js>> {
    ctx.json_parse(value.to_string())
}

fn url_parse_js<'js>(ctx: Ctx<'js>, input: String, base: Option<String>) -> Result<Value<'js>> {
    private_json(&ctx, serde_json::json!(url_parse(input, base)))
}

fn url_set_js<'js>(ctx: Ctx<'js>, href: String, key: String, value: String) -> Result<Value<'js>> {
    private_json(&ctx, serde_json::json!(url_set(href, key, value)))
}

fn form_parse_js<'js>(ctx: Ctx<'js>, input: String) -> Result<Value<'js>> {
    let pairs: Vec<_> = form_parse(input).into_iter().map(|List(pair)| pair).collect();
    private_json(&ctx, serde_json::json!(pairs))
}

fn bidi_direction(value: String) -> Option<&'static str> {
    use unicode_bidi::BidiClass;
    value.chars().find_map(|c| match unicode_bidi::bidi_class(c) {
        BidiClass::L => Some("ltr"),
        BidiClass::R | BidiClass::AL => Some("rtl"),
        _ => None,
    })
}

fn ip_address(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()
}

fn cookie_domain_matches(host: String, domain: String) -> bool {
    host == domain || (!ip_address(&host) && host.strip_suffix(&domain).is_some_and(|prefix| prefix.ends_with('.')))
}

fn cookie_public_suffix(host: String) -> bool {
    !ip_address(&host) && psl::suffix_str(&host) == Some(host.as_str())
}

fn cookie_site(href: String) -> Option<String> {
    let url = Url::parse(&href).ok()?;
    let host = quirks::hostname(&url);
    let domain = if ip_address(host) { host } else { psl::domain_str(host).unwrap_or(host) };
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        scheme => scheme,
    };
    Some(format!("{scheme}://{domain}"))
}

/// A URL's parts as `URL` shows them: href, origin, protocol, username,
/// password, host, hostname, port, pathname, search, hash.
fn parts(u: &Url) -> Vec<String> {
    let origin = quirks::origin(u);
    [
        quirks::href(u),
        &origin,
        quirks::protocol(u),
        quirks::username(u),
        quirks::password(u),
        quirks::host(u),
        quirks::hostname(u),
        quirks::port(u),
        quirks::pathname(u),
        quirks::search(u),
        quirks::hash(u),
    ]
    .map(str::to_string)
    .to_vec()
}

/// `new URL(input, base)`: the parts, or nothing when either doesn't parse.
fn url_parse(input: String, base: Option<String>) -> Option<Vec<String>> {
    let base = match base {
        Some(b) => Some(Url::parse(&b).ok()?),
        None => None,
    };
    Url::options().base_url(base.as_ref()).parse(&input).ok().map(|u| parts(&u))
}

/// A `URL` setter on `href`: the new parts. A value a setter refuses
/// leaves the URL as it was; only an `href` that doesn't parse is nothing
/// (the setter throws).
fn url_set(href: String, key: String, value: String) -> Option<Vec<String>> {
    let mut u = Url::parse(&href).ok()?;
    let v = value.as_str();
    match key.as_str() {
        "href" => quirks::set_href(&mut u, v).ok()?,
        "protocol" => quirks::set_protocol(&mut u, v).unwrap_or(()),
        "username" => quirks::set_username(&mut u, v).unwrap_or(()),
        "password" => quirks::set_password(&mut u, v).unwrap_or(()),
        "host" => quirks::set_host(&mut u, v).unwrap_or(()),
        "hostname" => quirks::set_hostname(&mut u, v).unwrap_or(()),
        "port" => quirks::set_port(&mut u, v).unwrap_or(()),
        "pathname" => quirks::set_pathname(&mut u, v),
        "search" => quirks::set_search(&mut u, v),
        "hash" => quirks::set_hash(&mut u, v),
        _ => {}
    }
    Some(parts(&u))
}

/// `application/x-www-form-urlencoded` text as name-value pairs.
fn form_parse(s: String) -> Vec<List<(String, String)>> {
    form_urlencoded::parse(s.as_bytes()).map(|(k, v)| List((k.into_owned(), v.into_owned()))).collect()
}

fn form_serialize(pairs: Vec<List<(String, String)>>) -> String {
    form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs.iter().map(|List((k, v))| (k, v))).finish()
}

fn input_color<'js>(ctx: Ctx<'js>, value: String, alpha: bool, p3: bool) -> Result<Value<'js>> {
    let (value, unsupported) = crate::input_color::sanitize(&value, alpha, p3);
    private_json(&ctx, serde_json::json!({"value":value,"unsupported":unsupported}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(input: &str) -> Option<String> {
        url_parse(input.into(), Some("https://app.example/shop/item?x=1".into())).map(|p| p[6].clone())
    }

    #[test]
    fn direction_uses_the_first_strong_unicode_character() {
        for (text, direction) in [("123", None), ("123 שלום", Some("rtl")), ("a שלום", Some("ltr")), ("𞤀", Some("rtl")), ("你好", Some("ltr"))] {
            assert_eq!(bidi_direction(text.into()), direction);
        }
    }

    #[test]
    fn cookie_scope_uses_native_public_suffix_and_ip_rules() {
        for host in ["github.io", "co.uk", "bar.ck"] {
            assert!(cookie_public_suffix(host.into()), "{host}");
        }
        for host in ["mine.github.io", "www.ck", "127.0.0.1", "[::1]"] {
            assert!(!cookie_public_suffix(host.into()), "{host}");
        }
        assert!(cookie_domain_matches("sub.app.example".into(), "app.example".into()));
        assert!(!cookie_domain_matches("evilapp.example".into(), "app.example".into()));
        assert!(!cookie_domain_matches("127.0.0.1".into(), "0.0.1".into()));
        for (url, site) in [
            ("https://a.example.co.uk/x", "https://example.co.uk"),
            ("https://mine.github.io/", "https://mine.github.io"),
            ("wss://sub.app.example/", "https://app.example"),
            ("http://[::1]/", "http://[::1]"),
        ] {
            assert_eq!(cookie_site(url.into()).as_deref(), Some(site));
        }
    }

    #[test]
    fn urls_parse_as_a_browser_parses_them() {
        // Lookalike and numeric hosts come out as a browser resolves them.
        assert_eq!(host("https://аpple.com").as_deref(), Some("xn--pple-43d.com"));
        assert_eq!(host("https://ＥＶＩＬ.example").as_deref(), Some("evil.example"));
        assert_eq!(host("http://0x7f.1/").as_deref(), Some("127.0.0.1"));
        assert_eq!(host("http://[::1]/").as_deref(), Some("[::1]"));
        assert_eq!(host("/\\evil.example").as_deref(), Some("evil.example"));
        assert_eq!(host("https://evil.example:0x50/"), None);
        let p = url_parse("../a b/%2e%2e/c?q=1 2#h".into(), Some("https://app.example/x/y/z".into())).unwrap();
        assert_eq!((p[0].as_str(), p[1].as_str()), ("https://app.example/x/c?q=1%202#h", "https://app.example"));
    }

    #[test]
    fn setters_keep_what_they_refuse() {
        let href = "https://app.example/a?b=1".to_string();
        assert_eq!(url_set(href.clone(), "pathname".into(), "x y".into()).unwrap()[0], "https://app.example/x%20y?b=1");
        assert_eq!(url_set(href.clone(), "port".into(), "x".into()).unwrap()[0], href);
        assert_eq!(url_set(href.clone(), "protocol".into(), "mailto".into()).unwrap()[0], href);
        assert!(url_set(href, "href".into(), "no scheme".into()).is_none());
    }

    #[test]
    fn forms_encode_as_a_browser_encodes_them() {
        let pairs = form_parse("a=1+2&b=%zz&c".into());
        let flat: Vec<(String, String)> = pairs.into_iter().map(|List(p)| p).collect();
        assert_eq!(flat, [("a".into(), "1 2".into()), ("b".into(), "%zz".into()), ("c".into(), String::new())]);
        assert_eq!(form_serialize(vec![List(("q".into(), "a b!&é".into()))]), "q=a+b%21%26%C3%A9");
    }
}
