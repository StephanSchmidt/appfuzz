use appfuzz_core::{markup, urls};

#[test]
fn static_script_checks_distinguish_foreign_text_from_executable_scripts() {
    for html in [
        "<math><script>fetch('https://evil.example/');</script></math>",
        "<math><script src='https://evil.example/x.js'></script></math>",
        "<math><object></object><iframe srcdoc='hello'></iframe></math>",
        "<svg><object></object></svg>",
    ] {
        assert!(markup::scripts(html).is_empty(), "{html}");
        assert!(markup::unpinned_scripts(html, &[]).is_empty(), "{html}");
        assert!(urls::in_html(html).iter().all(|u| u.source != "script" && u.trigger != "load"), "{html}");
    }
    for html in [
        "<script>void 0;</script>",
        "<svg><script>void 0;</script></svg>",
        "<svg><foreignObject><script>void 0;</script></foreignObject></svg>",
        "<math><mtext><script>void 0;</script></mtext></math>",
        "<math><annotation-xml encoding='text/html'><script>void 0;</script></annotation-xml></math>",
        "<math><mrow onclick='go()'>click</mrow></math>",
    ] {
        assert!(!markup::scripts(html).is_empty(), "{html}");
    }
}

#[test]
fn static_script_loads_use_the_attribute_for_the_scripts_namespace() {
    for (html, host) in [
        ("<script src='https://html.example/a.js'></script>", Some("html.example")),
        (
            "<svg><script href='https://svg.example/a.js' xlink:href='https://ignored.example/b.js' src='https://wrong.example/c.js'></script></svg>",
            Some("svg.example"),
        ),
        ("<svg><script xlink:href='https://legacy.example/a.js'></script></svg>", Some("legacy.example")),
        ("<svg><script href='' xlink:href='https://ignored.example/a.js'></script></svg>", None),
        ("<svg><script src='https://ignored.example/a.js'></script></svg>", None),
        ("<script href='https://ignored.example/a.js'></script>", None),
        ("<math><script src='https://ignored.example/a.js' href='https://ignored.example/b.js'></script></math>", None),
    ] {
        let findings = markup::unpinned_scripts(html, &[]);
        let hosts: Vec<_> = findings.iter().map(|(host, _)| host.as_str()).collect();
        assert_eq!(hosts, host.into_iter().collect::<Vec<_>>(), "{html}");
        let loads: Vec<_> = urls::in_html(html).into_iter().filter(|u| u.trigger == "load").collect();
        if let Some(host) = host {
            assert!(loads.iter().any(|u| u.url.contains(host)), "{html}: {loads:?}");
        } else {
            assert!(loads.iter().all(|u| !u.url.contains("ignored.example")), "{html}: {loads:?}");
        }
    }
}

#[test]
fn foreign_script_text_cannot_add_import_map_entries_or_remote_script_imports() {
    let html = r#"<math><script type='importmap'>{"imports":{"lib":"https://inert.example/lib.js"}}</script>
        <script>import 'https://inert.example/direct.js';</script></math>
        <script type='module'>import 'lib';</script>"#;
    assert!(markup::unpinned_scripts(html, &[]).is_empty());
    assert!(urls::in_html(html).iter().filter(|u| u.source == "script").all(|u| !u.url.contains("inert.example")));
}

#[test]
fn deep_markup_fallback_keeps_all_potential_script_sources_and_inline_imports() {
    let html = format!(
        "{}<script src='https://html.example/a.js' href='https://svg.example/b.js' xlink:href='https://legacy.example/c.js'>import 'https://inline.example/d.js';</script>",
        "<div>".repeat(1001)
    );
    let findings = markup::unpinned_scripts(&html, &[]);
    let hosts: std::collections::BTreeSet<_> = findings.iter().map(|(host, _)| host.as_str()).collect();
    assert_eq!(hosts, ["html.example", "svg.example", "legacy.example", "inline.example"].into());
}
