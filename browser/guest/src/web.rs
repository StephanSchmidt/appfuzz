//! `globalThis.__native`: the Web APIs the shim takes from Rust, where a
//! browser's behaviour is a parser appfuzz-core already uses: URLs by the
//! WHATWG rules (the `url` crate, which judges where requests go), so a
//! page's own checks (`new URL(next).host === location.host`) parse as in
//! a browser.

use rquickjs::convert::List;
use rquickjs::{Ctx, Function, Object, Result};
use url::{Url, form_urlencoded, quirks};

pub fn install(ctx: &Ctx<'_>) -> Result<()> {
    let n = Object::new(ctx.clone())?;
    n.set("url", Function::new(ctx.clone(), url_parse)?)?;
    n.set("urlSet", Function::new(ctx.clone(), url_set)?)?;
    n.set("formParse", Function::new(ctx.clone(), form_parse)?)?;
    n.set("formSerialize", Function::new(ctx.clone(), form_serialize)?)?;
    ctx.globals().set("__native", n)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host(input: &str) -> Option<String> {
        url_parse(input.into(), Some("https://app.example/shop/item?x=1".into())).map(|p| p[6].clone())
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
