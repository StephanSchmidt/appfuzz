use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(html: &str) -> (RunRecord, Value) {
    visit_planned(html, json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}))
}

fn visit_planned(html: &str, plan: Value) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = Plan::parse(&plan.to_string()).unwrap();
    let r = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    let report: Value = serde_json::from_str(r.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    (r, report)
}

/// A page's own checks (`new URL(next).host === location.host`) decide as
/// in a browser: URLs parse by the WHATWG rules, as appfuzz judges them.
#[test]
fn urls_parse_as_a_browser_parses_them() {
    let script = r#"
        const host = (u) => { try { return new URL(u, location.href).hostname; } catch { return 'invalid'; } };
        const u = new URL('https://app.example/a?x=1');
        u.searchParams.append('q', 'a b!');
        const v = new URL('https://app.example/p?a=1');
        v.search = '?b=2';
        v.port = 'x';
        v.protocol = 'mailto';
        console.log(JSON.stringify([
          host('https://аpple.com'), host('https://ＥＶＩＬ.example'), host('http://0x7f.1/'), host('http://[::1]/'),
          host('/\\evil.example'), host('https://evil.example:0x50/'),
          new URL('../a b/%2e%2e/c?q=1 2#h', 'https://app.example/x/y/z').href,
          u.href, v.href, v.searchParams.get('b'), new URLSearchParams('a=1+2&b=%zz&c').toString(),
          [...new URLSearchParams([['x', 'é&']])].join(), String(new URLSearchParams({ k: 'v w' })),
        ]));
    "#;
    let (_, report) = visit(&format!("<!doctype html><script>{script}</script>"));
    let seen: Value = serde_json::from_str(report["console"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        seen,
        json!([
            "xn--pple-43d.com",
            "evil.example",
            "127.0.0.1",
            "[::1]",
            "evil.example",
            "invalid",
            "https://app.example/x/c?q=1%202#h",
            "https://app.example/a?x=1&q=a+b%21",
            "https://app.example/p?b=2",
            "2",
            "a=1+2&b=%25zz&c=",
            "x,é&",
            "k=v+w"
        ])
    );
}

#[test]
fn fragments_and_omitted_document_elements_keep_their_visible_body_content() {
    for html in [
        "visible",
        "<p>visible</p>",
        "<!doctype html><p>visible</p>",
        "<html lang=en><p>visible</p></html>",
        "<body class=page><p>visible</p></body>",
        "<head><title>title</title></head><body><p>visible</p></body>",
        "<!doctype html><html><head><title>title</title></head><body><p>visible</p></body></html>",
    ] {
        let (_, report) = visit(html);
        assert_eq!(report["text"], "visible", "{html}: {report}");
    }
}

#[test]
fn empty_documents_have_a_usable_html_head_and_body() {
    let (_, report) = visit("");
    assert_eq!(report["text"], "");
    let (_, report) =
        visit("<script>console.log(document.documentElement.localName,document.head.parentNode.localName,document.body.parentNode.localName);</script>");
    assert_eq!(report["console"][0]["text"], "html html html");
}

#[test]
fn raw_text_comments_and_inert_templates_cannot_rewrite_document_structure_or_run_scripts() {
    let (r, report) = visit(
        r#"<!doctype html>
        <!-- <html><head></head><body id=forged> -->
        <noscript><script>fetch('/inert-noscript');</script></noscript>
        <textarea><html><body><script>fetch('/inert-textarea');</script></body></html></textarea>
        <template><script>fetch('/inert-template');</script></template>
        <p id=real>visible</p>
        <script>const bait='<html><head></head><body id=forged>';
        console.log(document.documentElement.localName,document.getElementById('real').parentNode.localName,document.getElementById('forged'));</script>"#,
    );
    assert_eq!(report["console"][0]["text"], "html body null", "{report}");
    assert!(r.events.iter().all(|e| e.func != FETCH_OWN), "inert content made requests: {:?}", r.events);
}

#[test]
fn html_tree_building_inserts_table_sections_and_fosters_stray_text() {
    let (_, report) = visit("<table>before<tr><td>cell</td></tr>after</table><p>visible</p>");
    assert_eq!(report["text"], "beforeaftercellvisible");
    let (_, report) = visit("<table><tr><td>cell</td></tr></table><script>console.log(document.querySelector('td').parentNode.parentNode.localName);</script>");
    assert_eq!(report["console"][0]["text"], "tbody");
}

#[test]
fn svg_integration_points_restore_the_html_namespace() {
    let (_, report) = visit(
        "<svg><foreignObject><p id=inside>visible</p></foreignObject></svg><math><mi id=math>x</mi></math><script>console.log(document.getElementById('inside').namespaceURI,document.getElementById('math').namespaceURI);</script>",
    );
    assert_eq!(report["console"][0]["text"], "http://www.w3.org/1999/xhtml http://www.w3.org/1998/Math/MathML");
}

#[test]
fn domparser_html_documents_get_implied_elements_while_xml_keeps_its_root() {
    let (_, report) = visit(
        r#"<!doctype html><html><head></head><body><script>
        const html=new DOMParser().parseFromString('<p>parsed</p>','text/html');
        const xml=new DOMParser().parseFromString('<root><item>xml</item></root>','text/xml');
        const inert=new DOMParser().parseFromString('<noscript><p id=parsed>parsed</p></noscript>','text/html');
        console.log(html.documentElement.localName,html.body.textContent,xml.documentElement.localName,inert.getElementById('parsed').textContent);
    </script></body></html>"#,
    );
    assert_eq!(report["console"][0]["text"], "html parsed root parsed");
}

#[test]
fn document_metadata_attributes_and_nested_template_contents_survive_tree_conversion() {
    let (_, report) = visit(
        r#"<!--before--><!doctype html><html lang=EN><head><title>A&amp;B</title></head><body class=page>
        <template id=outer><p data-name='A&amp;B'>inside</p><template id=inner><i>deep</i></template></template>
        <script>const t=document.getElementById('outer');console.log(document.doctype.name,document.compatMode,document.title,document.documentElement.lang,document.body.className,t.childNodes.length,t.content.querySelector('p').getAttribute('data-name'),t.content.querySelector('#inner').content.textContent);</script>
    </body></html>"#,
    );
    assert_eq!(report["console"][0]["text"], "html CSS1Compat A&B EN page 0 A&B deep", "{report}");
}

#[test]
fn document_fragment_text_content_reads_descendants_and_replaces_children() {
    let (_, report) = visit(
        r#"<script>
        const f=document.createDocumentFragment(),el=document.createElement('b');el.textContent='nested';
        f.append('plain',document.createComment('hidden'),el);console.log(f.textContent);
        f.textContent='replacement';console.log(f.childNodes.length,f.firstChild.nodeType,f.textContent);
        f.textContent=null;console.log(f.childNodes.length,JSON.stringify(f.textContent));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, vec!["plainnested", "1 3 replacement", "0 \"\""]);
}

#[test]
fn svg_elements_keep_their_nearest_owning_svg_and_templates_start_a_detached_tree() {
    let (_, report) = visit(
        r#"<svg id=outer><g id=g><svg id=inner><circle id=c /></svg></g>
        <foreignObject><template id=t><svg id=detached><g id=tg /></svg></template></foreignObject></svg>
        <script>const byId=id=>document.getElementById(id);const t=byId('t').content;
        console.log(byId('outer').ownerSVGElement,byId('g').ownerSVGElement.id,byId('inner').ownerSVGElement.id,byId('c').ownerSVGElement.id,t.querySelector('#detached').ownerSVGElement,t.querySelector('#tg').ownerSVGElement.id);</script>"#,
    );
    assert_eq!(report["console"][0]["text"], "null outer outer inner null detached");
}

#[test]
fn mathml_scripts_are_inert_while_html_svg_and_integration_point_scripts_run() {
    let (r, _) = visit(
        r#"<math><script>fetch('/inert-math');</script><mrow onclick="fetch('/math-handler')">click</mrow>
        <mtext><script>fetch('/html-in-math-text');</script></mtext>
        <annotation-xml encoding='text/html'><script>fetch('/html-in-math-annotation');</script></annotation-xml></math>
        <svg><script>fetch('/svg');</script><foreignObject><script>fetch('/html-in-svg');</script></foreignObject></svg>
        <script>fetch('/html');</script>"#,
    );
    let paths: std::collections::BTreeSet<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/math-handler", "/html-in-math-text", "/html-in-math-annotation", "/svg", "/html-in-svg", "/html"].into());
}

#[test]
fn svg_script_urls_use_href_then_xlink_href_and_ignore_src() {
    for (html, paths) in [
        ("<svg><script href='/modern.js' xlink:href='/legacy.js' src='/ignored.js'></script></svg>", vec!["/modern.js", "/loaded"]),
        ("<svg><script xlink:href='/legacy.js'></script></svg>", vec!["/legacy.js", "/loaded"]),
        ("<svg><script href='' xlink:href='/legacy.js'></script></svg>", vec!["/", "/loaded"]),
        ("<svg><script src='/ignored.js'>fetch('/inline');</script></svg>", vec!["/inline"]),
        ("<script href='/ignored.js'>fetch('/inline');</script>", vec!["/inline"]),
    ] {
        let plan = json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"fetch('/loaded');"}}}});
        let (r, _) = visit_planned(html, plan);
        let actual: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
        assert_eq!(actual, paths, "{html}");
    }
}

#[test]
fn dynamically_created_scripts_keep_their_namespace_and_svg_names_are_case_sensitive() {
    let (r, _) = visit(
        r#"<script>
        for(const [ns,id] of [['http://www.w3.org/1998/Math/MathML','math'],[null,'null'],['urn:custom','custom'],['http://www.w3.org/2000/svg','svg'],['http://www.w3.org/1999/xhtml','html']]) {
            const s=document.createElementNS(ns,'script');s.textContent="fetch('/"+id+"');";document.body.append(s);
        }
        const upper=document.createElementNS('http://www.w3.org/2000/svg','Script');upper.textContent="fetch('/inert-uppercase-svg');";document.body.append(upper);
        const upperNS=document.createElementNS('http://www.w3.org/1999/xhtml','SCRIPT');upperNS.textContent="fetch('/inert-uppercase-namespaced-html');";document.body.append(upperNS);
        const html=document.createElement('SCRIPT');html.textContent="fetch('/uppercase-html');";document.body.append(html);
    </script>"#,
    );
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/html", "/svg", "/uppercase-html"], "each created script executes only once");
}

#[test]
fn element_creation_converts_names_once_and_only_folds_ascii_in_html() {
    let (r, report) = visit(
        r#"<script>
        let htmlNames=0,svgNames=0;
        const html=document.createElement({toString(){return ++htmlNames===1?'SCRIPT':'div';}});
        html.textContent="fetch('/coerced-html');";document.body.append(html);
        const svg=document.createElementNS('http://www.w3.org/2000/svg',{toString(){return ++svgNames===1?'script':'g';}});
        svg.textContent="fetch('/coerced-svg');";document.body.append(svg);
        console.log(document.createElement('ÄTAG').localName,htmlNames,svgNames);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "Ätag 1 1");
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/coerced-html", "/coerced-svg"]);
}

#[test]
fn shadowing_dom_names_and_namespaces_cannot_hide_real_scripts_or_activate_foreign_text() {
    let (r, _) = visit(
        r#"<script>
        const later=document.getElementById('later');Object.defineProperty(later,'namespaceURI',{value:'urn:inert'});Object.defineProperty(later,'localName',{value:'inert'});
        const real=document.createElement('script');real.textContent="fetch('/created-real');";
        Object.defineProperty(real,'namespaceURI',{value:'urn:inert'});Object.defineProperty(real,'localName',{value:'inert'});document.body.append(real);
        const math=document.createElementNS('http://www.w3.org/1998/Math/MathML','script');math.textContent="fetch('/inert-math');";
        Object.defineProperty(math,'namespaceURI',{value:'http://www.w3.org/1999/xhtml'});document.body.append(math);
    </script><script id=later>fetch('/parsed-real');</script>"#,
    );
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/created-real", "/parsed-real"]);
}

#[test]
fn dynamically_inserted_batches_do_not_replace_remaining_page_or_parent_batch_scripts() {
    let (_, report) = visit(
        r#"<script>
        console.log('a');
        const d=document.createElement('script');d.textContent="console.log('d');const e=document.createElement('script');e.textContent=\"console.log('e');\";document.body.append(e);";document.body.append(d);
        const d2=document.createElement('script');d2.textContent="console.log('d2');";document.body.append(d2);
    </script><script>console.log('b');</script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["a", "d", "e", "d2", "b"]);
}

#[test]
fn external_script_completion_events_keep_the_original_load_even_if_its_url_attribute_changes() {
    for html in
        ["<script src='/external.js' onload=\"fetch('/loaded');\"></script>", "<svg><script href='/external.js' onload=\"fetch('/loaded');\"></script></svg>"]
    {
        let plan = json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"document.currentScript.removeAttribute('src');document.currentScript.removeAttribute('href');"}}}});
        let (r, _) = visit_planned(html, plan);
        let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["/external.js", "/loaded"], "{html}");
    }
}

#[test]
fn prefixed_html_and_svg_scripts_execute_with_their_local_names_and_namespaces() {
    let (r, report) = visit(
        r#"<script>
        for(const [ns,name,path] of [['http://www.w3.org/2000/svg','v:script','svg'],['http://www.w3.org/1999/xhtml','h:script','html'],['http://www.w3.org/1998/Math/MathML','m:script','math']]) {
            const s=document.createElementNS(ns,name);s.textContent="fetch('/"+path+"');";
            console.log(JSON.stringify([s.namespaceURI,s.prefix,s.localName,s.tagName,s.nodeName]));document.body.append(s);
        }
    </script>"#,
    );
    let logs: Vec<Value> = report["console"].as_array().unwrap().iter().map(|v| serde_json::from_str(v["text"].as_str().unwrap()).unwrap()).collect();
    assert_eq!(
        logs,
        vec![
            json!(["http://www.w3.org/2000/svg", "v", "script", "v:script", "v:script"]),
            json!(["http://www.w3.org/1999/xhtml", "h", "script", "H:SCRIPT", "H:SCRIPT"]),
            json!(["http://www.w3.org/1998/Math/MathML", "m", "script", "m:script", "m:script"])
        ]
    );
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/html", "/svg"]);
}

#[test]
fn namespace_creation_validates_prefixes_local_names_and_reserved_namespace_pairs() {
    let (_, report) = visit(
        r#"<script>
        const cases=[[null,'p:script','NamespaceError'],['','p:script','NamespaceError'],['urn:test','xml:part','NamespaceError'],['urn:test','xmlns','NamespaceError'],['urn:test','xmlns:p','NamespaceError'],['http://www.w3.org/2000/xmlns/','p:part','NamespaceError'],['urn:test','','InvalidCharacterError'],['urn:test',':part','InvalidCharacterError'],['urn:test','p:','InvalidCharacterError'],['urn:test','p:a b','InvalidCharacterError'],['urn:test','p:a/b','InvalidCharacterError'],['urn:test','p:a>b','InvalidCharacterError'],['urn:test','p:a\0b','InvalidCharacterError'],['urn:test','p:1bad','InvalidCharacterError'],[null,'p:1bad','InvalidCharacterError'],['urn:test','p:script\n','InvalidCharacterError'],['urn:test','p\n:script','InvalidCharacterError']];
        for(const [ns,name,expected] of cases){let error='none';try{document.createElementNS(ns,name);}catch(e){error=e.name;if(!(e instanceof DOMException)||e.code!==(expected==='NamespaceError'?14:5))error+=':wrong-exception';}console.log(error===expected?'ok':name+':'+error);}
    </script>"#,
    );
    assert_eq!(report["console"].as_array().unwrap().len(), 17, "{report}");
    assert!(report["console"].as_array().unwrap().iter().all(|v| v["text"] == "ok"), "{report}");
}

#[test]
fn namespace_names_follow_current_dom_rules_without_unnecessary_xml_restrictions() {
    let (_, report) = visit(
        r#"<script>
        const cases=[['urn:test','1:part','1','part'],['urn:test','p:part:tail','p','part:tail'],['urn:test','p::part','p',':part'],['urn:test','p:a=b','p','a=b'],['urn:test','p:a"b','p','a"b'],['urn:test','Ä:Élem','Ä','Élem'],['urn:test','💧:part','💧','part'],['urn:test','XML:part','XML','part'],['http://www.w3.org/XML/1998/namespace','xml:lang','xml','lang'],['http://www.w3.org/2000/xmlns/','xmlns',null,'xmlns'],['http://www.w3.org/2000/xmlns/','xmlns:p','xmlns','p'],[null,'local',null,'local'],['','local',null,'local']];
        for(const [ns,name,prefix,local] of cases){const e=document.createElementNS(ns,name);console.log(e.namespaceURI===(ns||null)&&e.prefix===prefix&&e.localName===local?'ok':JSON.stringify([name,e.namespaceURI,e.prefix,e.localName]));}
    </script>"#,
    );
    assert_eq!(report["console"].as_array().unwrap().len(), 13, "{report}");
    assert!(report["console"].as_array().unwrap().iter().all(|v| v["text"] == "ok"), "{report}");
}

#[test]
fn cloned_namespace_elements_keep_prefixes_and_do_not_activate_literal_colon_or_mathml_tags() {
    let (r, report) = visit(
        r#"<svg id=literal><v:script>fetch('/inert-literal');</v:script><v:></v:></svg>
        <script>
        for(const ns of ['http://www.w3.org/2000/svg','http://www.w3.org/1999/xhtml','http://www.w3.org/1998/Math/MathML']) {
            const root=document.createElementNS(ns,'p:root'),s=document.createElementNS(ns,'p:script');
            s.textContent="fetch('/"+(ns.includes('svg')?'svg':ns.includes('xhtml')?'html':'inert-math')+"');";root.append(s);
            const copy=root.cloneNode(true),child=copy.firstChild;
            console.log(JSON.stringify([copy.namespaceURI,copy.prefix,copy.localName,child.namespaceURI,child.prefix,child.localName,copy.ownerDocument===document]));document.body.append(copy);
        }
        const literal=document.getElementById('literal').cloneNode(true);console.log(literal.firstChild.localName);document.body.append(literal);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs.len(), 4, "{report}");
    for (log, namespace) in logs[..3].iter().zip(["http://www.w3.org/2000/svg", "http://www.w3.org/1999/xhtml", "http://www.w3.org/1998/Math/MathML"]) {
        assert_eq!(serde_json::from_str::<Value>(log).unwrap(), json!([namespace, "p", "root", namespace, "p", "script", true]));
    }
    assert_eq!(logs[3], "v:script");
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/html", "/svg"]);
}

#[test]
fn shallow_script_clones_keep_url_attributes_and_parsed_foreign_clones_keep_their_namespace() {
    let (r, report) = visit_planned(
        r#"<math id=math><script>fetch('/inert-math');</script></math>
        <svg id=svg><g><svg><circle></circle></svg></g></svg><script>
        const s=document.createElementNS('http://www.w3.org/2000/svg','v:script');s.setAttribute('href','/cloned.js');
        s.textContent="fetch('/inert-child');";Object.defineProperty(s,'namespaceURI',{value:'urn:shadow'});
        const copy=s.cloneNode(false);console.log(copy.namespaceURI,copy.prefix,copy.localName,copy.childNodes.length,copy.getAttribute('href'));document.body.append(copy);
        const math=document.getElementById('math').cloneNode(true);console.log(math.namespaceURI,math.firstChild.namespaceURI);document.body.append(math);
        const svg=document.getElementById('svg').cloneNode(true),g=svg.firstChild,inner=g.firstChild,circle=inner.firstChild;
        console.log(svg.ownerSVGElement,g.ownerSVGElement===svg,inner.ownerSVGElement===svg,circle.ownerSVGElement===inner);
    </script>"#,
        json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"fetch('/loaded');"}}}}),
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        ["http://www.w3.org/2000/svg v script 0 /cloned.js", "http://www.w3.org/1998/Math/MathML http://www.w3.org/1998/Math/MathML", "null true true true"]
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/cloned.js", "/loaded"]);
}

#[test]
fn namespace_creation_coerces_each_argument_once_and_checks_required_arguments_first() {
    let (r, report) = visit(
        r#"<script>
        let namespaces=0,names=0;const s=document.createElementNS({toString(){namespaces++;return 'http://www.w3.org/2000/svg';}},{toString(){names++;return 'v:script';}});s.textContent="fetch('/once');";document.body.append(s);console.log(namespaces,names);
        let missing=0;try{document.createElementNS({toString(){missing++;return 'urn:test';}});}catch(e){console.log(e.name,missing);}
        for(const [ns,name] of [[{toString(){return '';}},'v:script'],[Symbol('ns'),'script'],['urn:test',Symbol('name')]]){try{document.createElementNS(ns,name);console.log('none');}catch(e){console.log(e.name);}}
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["1 1", "TypeError 0", "NamespaceError", "TypeError", "TypeError"]);
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/once"]);
}

#[test]
fn clones_use_the_owning_documents_element_class() {
    let (_, report) = visit(
        r#"<script>
        for(const [markup,mime] of [['<root><child/></root>','text/xml'],['<p>text</p>','text/html']]) {
            const d=new DOMParser().parseFromString(markup,mime),root=d.documentElement,copy=root.cloneNode(true);
            console.log(root.constructor===copy.constructor,root.firstChild.constructor===copy.firstChild.constructor,root.ownerDocument===copy.ownerDocument,copy.ownerDocument===d);
        }
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["true true true true", "true true true true"]);
}

#[test]
fn cloned_scripts_wait_for_the_active_page_and_can_run_after_adoption_or_in_shadow_trees() {
    for destination in ["detached", "page", "shadow"] {
        let html = format!(
            r#"<script>
            const d=new DOMParser().parseFromString('<div><script>fetch("/cloned");<\/script></div>','text/html');
            const copy=d.querySelector('div').cloneNode(true);
            if('{destination}'==='detached'){{
                Object.defineProperty(copy.firstChild,'isConnected',{{value:true}});copy.firstChild.getRootNode=()=>document;
                d.body.append(copy);
            }}else if('{destination}'==='shadow'){{
                const host=document.createElement('div');document.body.append(host);host.attachShadow({{mode:'closed'}}).append(copy);
            }}else document.body.append(copy);
        </script>"#
        );
        let (r, _) = visit(&html);
        let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
        assert_eq!(paths, if destination == "detached" { vec![] } else { vec!["/cloned"] }, "{destination}");
    }
}

#[test]
fn deep_clones_schedule_scripts_in_tree_order() {
    let (_, report) = visit(
        r#"<script>
        const root=document.createElement('div');
        for(const text of ['a','b','c']) {
            const container=document.createElement('div'),s=document.createElement('script');
            s.textContent='console.log('+JSON.stringify(text)+');';container.append(s);root.append(container);
        }
        document.body.append(root.cloneNode(true));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["a", "b", "c"]);
}

#[test]
fn fresh_scripts_from_other_documents_execute_when_inserted_into_the_active_page() {
    let (r, _) = visit(
        r#"<script>
        const html=new DOMParser().parseFromString('','text/html'),xml=new DOMParser().parseFromString('<root/>','text/xml');
        for(const [owner,ns,name,path] of [[html,undefined,'SCRIPT','html'],[html,'http://www.w3.org/2000/svg','v:script','svg'],[xml,'http://www.w3.org/1999/xhtml','h:script','xml-html']]) {
            const s=ns===undefined?owner.createElement(name):owner.createElementNS(ns,name);s.textContent="fetch('/"+path+"');";document.body.append(s);
        }
        const inert=xml.createElement('script');inert.textContent="fetch('/inert-xml');";document.body.append(inert);
    </script>"#,
    );
    let mut paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["/html", "/svg", "/xml-html"]);
}

#[test]
fn documents_created_by_domparser_share_namespace_validation_and_case_rules() {
    let (_, report) = visit(
        r#"<script>
        const html=new DOMParser().parseFromString('','text/html'),xml=new DOMParser().parseFromString('<root/>','text/xml');
        for(const d of [html,xml]) {
            let error='none';try{d.createElementNS(null,'p:script');}catch(e){error=e.name;}
            const plain=d.createElement('Mixed'),qualified=d.createElementNS('http://www.w3.org/2000/svg','p:Mixed');
            console.log(JSON.stringify([error,plain.localName,plain.namespaceURI,qualified.localName,qualified.prefix,qualified.tagName]));
        }
    </script>"#,
    );
    let logs: Vec<Value> = report["console"].as_array().unwrap().iter().map(|v| serde_json::from_str(v["text"].as_str().unwrap()).unwrap()).collect();
    assert_eq!(
        logs,
        [
            json!(["NamespaceError", "mixed", "http://www.w3.org/1999/xhtml", "Mixed", "p", "p:Mixed"]),
            json!(["NamespaceError", "Mixed", null, "Mixed", "p", "p:Mixed"])
        ]
    );
}

#[test]
fn inserting_a_foreign_subtree_adopts_elements_attributes_text_and_fragments() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html');
        for(const method of ['append','prepend','appendChild','insertBefore','replaceChild','before','after','replaceWith','replaceChildren','insertAdjacentElement','fragment']) {
            const target=document.createElement('div'),anchor=document.createElement('i');target.append(anchor);document.body.append(target);
            const root=foreign.createElement('div'),child=foreign.createElement('span'),text=foreign.createTextNode('text'),comment=foreign.createComment('comment');
            child.setAttribute('data-value','value');root.append(child,text,comment);
            const fragment=foreign.createDocumentFragment();
            if(method==='fragment'){fragment.append(root);target.append(fragment);}
            else if(method==='insertBefore'||method==='replaceChild')target[method](root,anchor);
            else if(['before','after','replaceWith'].includes(method))anchor[method](root);
            else if(method==='insertAdjacentElement')anchor.insertAdjacentElement('afterend',root);
            else target[method](root);
            console.log(method,[root,child,text,comment,child.attributes[0],...(method==='fragment'?[fragment]:[])].every(n=>n.ownerDocument===document));
        }
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "append true",
            "prepend true",
            "appendChild true",
            "insertBefore true",
            "replaceChild true",
            "before true",
            "after true",
            "replaceWith true",
            "replaceChildren true",
            "insertAdjacentElement true",
            "fragment true"
        ]
    );
}

#[test]
fn adoption_callbacks_observe_the_destination_document() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html');
        customElements.define('adoption-check',class extends HTMLElement {
            connectedCallback(){console.log('connected',this.ownerDocument===document?'main':'foreign',this.isConnected);}
            disconnectedCallback(){console.log('disconnected',this.ownerDocument===document?'main':'foreign',this.isConnected);}
            adoptedCallback(oldDoc,newDoc){console.log('adopted',oldDoc===document?'main':'foreign',newDoc===document?'main':'foreign',this.isConnected);}
        });
        const el=document.createElement('adoption-check');document.body.append(el);foreign.body.append(el);document.body.append(el);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "connected main true",
            "disconnected foreign true",
            "adopted main foreign true",
            "connected foreign true",
            "disconnected main true",
            "adopted foreign main true",
            "connected main true"
        ]
    );
}

#[test]
fn adoption_keeps_the_old_documents_removal_observer_record() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html'),el=document.createElement('div');document.body.append(el);
        const observer=new MutationObserver(records=>console.log('removed',records.reduce((n,r)=>n+r.removedNodes.length,0)));
        observer.observe(document.body,{childList:true});foreign.body.append(el);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["removed 1"]);
}

#[test]
fn adoption_updates_closed_shadow_roots_and_their_descendants() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html'),host=foreign.createElement('div'),shadow=host.attachShadow({mode:'closed'}),child=foreign.createElement('span'),text=foreign.createTextNode('text');
        child.setAttribute('data-value','value');shadow.append(child,text);document.body.append(host);
        console.log(host.shadowRoot,[host,shadow,child,text,child.attributes[0]].every(n=>n.ownerDocument===document));
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "null true");
}

#[test]
fn nested_adoption_drains_already_queued_reactions_and_preserves_their_arguments() {
    let (_, report) = visit(
        r#"<script>
        const logs=[],foreign=new DOMParser().parseFromString('','text/html');let moved=false;
        customElements.define('reaction-node',class extends HTMLElement {
            connectedCallback(){logs.push([this.id,'connected',this.ownerDocument===document?'main':'foreign']);}
            disconnectedCallback(){logs.push([this.id,'disconnected',this.ownerDocument===document?'main':'foreign']);}
            adoptedCallback(oldDoc,newDoc){
                logs.push([this.id,'adopted',oldDoc===document?'main':'foreign',newDoc===document?'main':'foreign']);
                if(this.id==='parent'&&newDoc===foreign&&!moved){moved=true;document.body.append(this.firstChild);}
            }
        });
        const parent=document.createElement('reaction-node');parent.id='parent';const child=document.createElement('reaction-node');child.id='child';
        parent.append(child);document.body.append(parent);logs.length=0;foreign.body.append(parent);console.log(JSON.stringify(logs));
    </script>"#,
    );
    let logs: Value = serde_json::from_str(report["console"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        logs,
        json!([
            ["parent", "disconnected", "foreign"],
            ["parent", "adopted", "main", "foreign"],
            ["child", "disconnected", "main"],
            ["child", "adopted", "main", "foreign"],
            ["child", "connected", "main"],
            ["child", "disconnected", "main"],
            ["child", "adopted", "foreign", "main"],
            ["child", "connected", "main"],
            ["parent", "connected", "foreign"]
        ])
    );
}

#[test]
fn queued_adoption_callbacks_keep_the_function_selected_before_earlier_reactions_run() {
    let (_, report) = visit(
        r#"<script>
        const logs=[],foreign=new DOMParser().parseFromString('','text/html');let child;
        customElements.define('change-callback',class extends HTMLElement {
            disconnectedCallback(){if(this.id==='parent')child.adoptedCallback=()=>logs.push('replacement');}
            adoptedCallback(){if(this.id==='child')logs.push('original');}
        });
        const parent=document.createElement('change-callback');parent.id='parent';child=document.createElement('change-callback');child.id='child';
        parent.append(child);document.body.append(parent);foreign.body.append(parent);console.log(JSON.stringify(logs));
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], r#"["original"]"#);
}

#[test]
fn observers_follow_their_target_when_it_moves_to_another_document() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html'),el=document.createElement('div');document.body.append(el);
        const observer=new MutationObserver(records=>console.log('attribute',records.length));observer.observe(el,{attributes:true});
        foreign.body.append(el);el.setAttribute('data-value','changed');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["attribute 1"]);
}

#[test]
fn observers_can_watch_other_documents_and_disconnecting_one_keeps_other_observers_active() {
    let (_, report) = visit(
        r#"<script>
        const foreign=new DOMParser().parseFromString('','text/html'),el=foreign.createElement('div');foreign.body.append(el);
        const survivor=new MutationObserver(records=>console.log('survivor',records.length)),discarded=new MutationObserver(()=>console.log('discarded'));
        survivor.observe(el,{attributes:true});discarded.observe(el,{attributes:true});discarded.disconnect();el.setAttribute('data-value','changed');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["survivor 1"]);
}
