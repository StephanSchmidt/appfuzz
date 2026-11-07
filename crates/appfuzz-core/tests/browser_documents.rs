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
    let (r, report) = visit_unchecked(html, plan);
    assert_eq!(report["errors"], json!([]), "{report}");
    (r, report)
}

fn visit_unchecked(html: &str, plan: Value) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = Plan::parse(&plan.to_string()).unwrap();
    let r = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    let report: Value = serde_json::from_str(r.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
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
            const d=new DOMParser().parseFromString('','text/html'),original=d.createElement('div'),script=d.createElement('script');
            script.textContent='fetch("/cloned");';original.append(script);
            const copy=original.cloneNode(true);
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

/// htmx swaps in a response parsed in another document: text and comments
/// between its elements move with them, out of their old parent.
#[test]
fn text_and_comments_move_out_of_another_documents_tree() {
    let (_, report) = visit(
        r#"<div id=target></div><script>
        const parsed=new DOMParser().parseFromString('<body><template><p>a</p> <!--c--><p>b</p></template> tail</body>','text/html');
        const target=document.getElementById('target'),content=parsed.querySelector('template').content;
        while(content.firstChild)target.insertBefore(content.firstChild,null);
        while(parsed.body.lastChild.nodeType===3)target.append(parsed.body.lastChild);
        console.log(target.innerHTML,[...target.childNodes].every(n=>n.ownerDocument===document),content.childNodes.length);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "<p>a</p> <!--c--><p>b</p> tail true 0");
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

#[test]
fn document_clones_use_a_fresh_registry_and_own_all_copied_nodes_without_adoption_callbacks() {
    let (_, report) = visit(
        r#"<!doctype html><script>
        const logs=[];customElements.define('clone-check',class extends HTMLElement {
            constructor(){super();logs.push('constructor');}
            connectedCallback(){logs.push('connected');}
            adoptedCallback(){logs.push('adopted');}
        });
        const el=document.createElement('clone-check');el.setAttribute('data-value','value');el.append('text',document.createComment('comment'));document.body.append(el);logs.length=0;
        const copy=document.cloneNode(true),child=copy.querySelector('clone-check');
        logs.push([child.ownerDocument===copy,child.attributes[0].ownerDocument===copy,child.firstChild.ownerDocument===copy,child.lastChild.ownerDocument===copy,copy.doctype.ownerDocument===copy]);
        console.log(JSON.stringify(logs));
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "[[true,true,true,true,true]]");
}

#[test]
fn element_clones_preserve_the_class_implied_by_their_namespace() {
    let (_, report) = visit(
        r#"<script>
        for(const ns of [null,'urn:test','http://www.w3.org/1998/Math/MathML','http://www.w3.org/1999/xhtml','http://www.w3.org/2000/svg']) {
            const source=document.createElementNS(ns,'script'),copy=source.cloneNode(true);
            console.log(JSON.stringify([copy.namespaceURI,copy.constructor===source.constructor,copy instanceof HTMLElement]));
        }
    </script>"#,
    );
    let logs: Vec<Value> = report["console"].as_array().unwrap().iter().map(|v| serde_json::from_str(v["text"].as_str().unwrap()).unwrap()).collect();
    assert_eq!(
        logs,
        [
            json!([null, true, false]),
            json!(["urn:test", true, false]),
            json!(["http://www.w3.org/1998/Math/MathML", true, false]),
            json!(["http://www.w3.org/1999/xhtml", true, true]),
            json!(["http://www.w3.org/2000/svg", true, false])
        ]
    );
}

#[test]
fn document_clones_keep_document_type_and_distinguish_shallow_from_deep_copies() {
    let (_, report) = visit(
        r#"<!doctype html><!--leading--><script>
        const xml=new DOMParser().parseFromString('<Root a="v"><![CDATA[text]]><!--comment--></Root>','text/xml');
        for(const source of [document,xml])for(const deep of [false,true]) {
            const copy=source.cloneNode(deep);
            console.log(copy.constructor===source.constructor,copy.childNodes.length===(deep?source.childNodes.length:0),deep?copy.documentElement.ownerDocument===copy:copy.documentElement===null);
            if(deep&&source===document)console.log(copy.doctype.name,copy.compatMode);
            if(deep&&source===xml)console.log(copy.documentElement.localName,copy.documentElement.namespaceURI,copy.documentElement.firstChild.nodeType,copy.documentElement.firstChild.ownerDocument===copy,copy.documentElement.lastChild.ownerDocument===copy);
        }
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["true true true", "true true true", "html CSS1Compat", "true true true", "true true true", "Root null 4 true true"]);
}

#[test]
fn page_overrides_of_weakmap_cannot_prevent_script_cloning() {
    let (r, report) = visit(
        r#"<script>
        const source=document.createElement('script');source.textContent="fetch('/cloned');";
        const NativeWeakMap=WeakMap,get=NativeWeakMap.prototype.get,set=NativeWeakMap.prototype.set;let calls=0,copy;
        WeakMap=function(){calls++;throw Error('page constructor');};
        NativeWeakMap.prototype.get=NativeWeakMap.prototype.set=function(){calls++;throw Error('page method');};
        try{copy=source.cloneNode(true);}catch(e){}finally{WeakMap=NativeWeakMap;NativeWeakMap.prototype.get=get;NativeWeakMap.prototype.set=set;}
        console.log(calls,copy?.localName||'missing');if(copy)document.body.append(copy);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "0 script");
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/cloned"]);
}

#[test]
fn public_document_properties_cannot_inject_code_into_cloning() {
    let (_, report) = visit(
        r#"<script>
        const xml=new DOMParser().parseFromString('<root/>','text/xml');let calls=0,copy;
        for(const name of ['constructor','compatMode'])Object.defineProperty(xml,name,{get(){calls++;throw Error('page getter');}});
        Object.defineProperty(xml.documentElement,'nodeType',{get(){calls++;throw Error('page node type');}});
        try{copy=xml.cloneNode(true);}catch(e){}console.log(calls,copy?.documentElement.localName||'missing');
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "0 root");
}

#[test]
fn page_map_and_property_helpers_cannot_break_document_cloning() {
    let (_, report) = visit(
        r#"<script>
        const logs=[];
        for(const kind of ['map','define']) {
            const xml=new DOMParser().parseFromString('<!--before--><root/>','text/xml'),get=Map.prototype.get,define=Object.defineProperty;let calls=0,copy;
            const replacement=()=>{calls++;throw Error('page helper');};
            if(kind==='map')Map.prototype.get=replacement;else Object.defineProperty=replacement;
            try{copy=xml.cloneNode(true);}catch(e){}finally{Map.prototype.get=get;Object.defineProperty=define;}
            logs.push([calls,copy?.documentElement.localName||'missing']);
        }
        console.log(JSON.stringify(logs));
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], r#"[[0,"root"],[0,"root"]]"#);
}

#[test]
fn cloning_the_currently_executing_script_does_not_execute_it_again() {
    let (_, report) =
        visit(r#"<script>console.log('once');if(!window.cloned){window.cloned=true;document.head.append(document.currentScript.cloneNode(true));}</script>"#);
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["once"]);
}

#[test]
fn executed_script_state_survives_element_subtree_document_and_fragment_cloning() {
    for kind in ["script", "subtree", "document", "fragment"] {
        let html = format!(
            r#"<div id=tree><script id=ran>console.log('once');</script></div><script>
        const original=document.getElementById('ran');let copy;
        if('{kind}'==='script')copy=original.cloneNode(true);
        else if('{kind}'==='subtree')copy=document.getElementById('tree').cloneNode(true);
        else if('{kind}'==='document')copy=document.cloneNode(true).getElementById('ran');
        else{{const fragment=document.createDocumentFragment();fragment.append(original);copy=fragment.cloneNode(true);}}
        document.body.append(copy);
        </script>"#
        );
        let (_, report) = visit(&html);
        let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
        assert_eq!(logs, ["once"], "{kind}");
    }
}

#[test]
fn empty_inert_and_fresh_detached_scripts_can_execute_after_cloning() {
    let (_, report) = visit(
        r#"<script id=empty></script><script id=inert type=application/json>console.log('inert-copy');</script><script>
    const empty=document.getElementById('empty').cloneNode(true);empty.textContent="console.log('empty-copy');";document.body.append(empty);
    const inert=document.getElementById('inert').cloneNode(true);inert.type='';document.body.append(inert);
    const fresh=document.createElement('script');fresh.textContent="console.log('fresh-copy');";document.body.append(fresh.cloneNode(true));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["empty-copy", "inert-copy", "fresh-copy"]);
}

#[test]
fn parsed_and_nomodule_scripts_do_not_restart_when_cloned_into_the_active_page() {
    let (r, _) = visit(
        r#"<script id=nomodule nomodule>fetch('/nomodule');</script><script>
    const nomodule=document.getElementById('nomodule').cloneNode(true);nomodule.removeAttribute('nomodule');document.body.append(nomodule);
    const markup=code=>'<script>'+code+'</'+'script>';
    const holder=document.createElement('div');holder.innerHTML=markup("fetch('/fragment');");document.body.append(holder.firstChild.cloneNode(true));
    const parsed=new DOMParser().parseFromString(markup("fetch('/parsed');"),'text/html');document.body.append(parsed.querySelector('script').cloneNode(true));
    </script>"#,
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert!(paths.is_empty(), "{paths:?}");
}

#[test]
fn dynamically_inserted_inline_scripts_execute_before_insertion_returns() {
    let (_, report) = visit(
        r#"<script>
    const outer=document.currentScript,s=document.createElement('script');s.text='console.log("dynamic",document.currentScript===window.dynamic);';window.dynamic=s;
    console.log('before');document.head.append(s);console.log('after',document.currentScript===outer);
    document.body.append(s.cloneNode(true));
    s.text='console.log("changed");';
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["before", "dynamic true", "after true"]);
}

#[test]
fn script_insertion_prepares_the_entire_batch_before_running_its_first_script() {
    let (_, report) = visit(
        r#"<script>
    const a=document.createElement('script'),b=document.createElement('script');window.second=b;
    a.text='console.log("first",second.isConnected);document.body.append(second.cloneNode(true));';b.text='console.log("second");';
    document.body.append(a,b);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["first true", "second"]);
}

#[test]
fn scripts_prepared_in_inert_documents_stay_inert_after_moving_and_cloning() {
    let (r, _) = visit(
        r#"<script>
    const d=new DOMParser().parseFromString('','text/html'),s=d.createElement('script');s.text='fetch("/inactive");';d.body.append(s);
    document.body.append(s.cloneNode(true));document.body.append(s);
    const markup=code=>'<script>'+code+'</'+'script>';
    for(const kind of ['fragment','document'])for(const type of ['empty','json']){
      let script;
      if(kind==='fragment'){const holder=document.createElement('div');holder.innerHTML=type==='empty'?markup(''):markup('fetch("/json");').replace('<script>','<script type=application/json>');script=holder.firstChild;}
      else{const parsed=new DOMParser().parseFromString(type==='empty'?markup(''):markup('fetch("/json");').replace('<script>','<script type=application/json>'),'text/html');script=parsed.querySelector('script');}
      const copy=script.cloneNode(true);copy.type='';if(type==='empty')copy.text='fetch("/empty");';document.body.append(copy);
    }
    </script>"#,
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert!(paths.is_empty(), "{paths:?}");
}

#[test]
fn contextual_fragments_and_initial_template_scripts_execute_after_insertion() {
    let (_, report) = visit(
        r#"<template id=t><script>console.log('template');</script></template><script>
    document.body.append(document.getElementById('t').content.cloneNode(true));
    const range=document.createRange();range.selectNodeContents(document.body);
    document.body.append(range.createContextualFragment('<script>console.log("contextual");</'+'script>'));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["template", "contextual"]);
}

#[test]
fn script_preparation_reads_child_text_and_reacts_to_connected_text_changes() {
    let (_, report) = visit(
        r#"<script>
    const s=document.createElement('script'),span=document.createElement('span');span.textContent='console.log("descendant");';s.append(span);document.body.append(s);
    s.append('console.log("direct");');
    const t=document.createElement('script'),text=document.createTextNode('');t.append(text);document.head.append(t);text.data='console.log("data");';
    const inert=document.createElement('script');inert.type='application/json';inert.text='console.log("type-only");';document.body.append(inert);inert.type='';
    console.log('after');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["direct", "data", "after"]);
}

#[test]
fn external_script_preparation_survives_cloning_source_changes_and_coerced_attribute_names() {
    let (r, report) = visit_planned(
        r#"<script>
    const s=document.createElement('script');document.head.append(s);let names=0,values=0;
    s.setAttribute({toString(){names++;return 'SRC';}},{toString(){values++;return '/first.js';}});
    const copy=s.cloneNode(true);copy.src='/copy.js';document.head.append(copy);s.src='/changed.js';
    console.log('after',names,values);
    </script>"#,
        json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"console.log('loaded');"}}}}),
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/first.js"]);
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["after 1 1", "loaded"]);
}

#[test]
fn nested_inline_execution_restores_current_script_and_reports_errors_without_throwing_from_append() {
    let (_, report) = visit_unchecked(
        r#"<script>
    const outer=document.currentScript;
    const inner=document.createElement('script');window.innerScript=inner;
    inner.text='console.log("inner",document.currentScript===innerScript);const nested=document.createElement("script");nested.text="console.log(123);";document.body.append(nested);throw Error("inner failure");';
    try{document.head.append(inner);console.log('returned',document.currentScript===outer);}catch(e){console.log('caught');}
    document.body.append(inner.cloneNode(true));
    </script>"#,
        json!({}),
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["inner true", "123", "returned true"]);
    assert_eq!(report["errors"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["errors"][0]["message"], "inner failure");
}

#[test]
fn scripts_in_closed_shadow_trees_prepare_when_the_host_connects_despite_public_host_shadows() {
    let (_, report) = visit(
        r#"<script>
    const host=document.createElement('div'),root=host.attachShadow({mode:'closed'}),s=document.createElement('script');
    Object.defineProperty(root,'host',{value:document.createElement('div')});
    s.text='console.log("shadow");';root.append(s);console.log('detached');document.body.append(host);console.log('connected');
    document.body.append(s.cloneNode(true));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["detached", "shadow", "connected"]);
}

#[test]
fn script_mime_types_language_and_nomodule_keep_browser_preparation_behavior() {
    let (_, report) = visit(
        r#"<script>
    for(const type of ['text/javascript1.5','text/livescript','application/x-javascript',' \ttext/javascript\r\n','\u00a0text/javascript\u00a0']){
      const s=document.createElement('script');s.type=type;s.text='console.log('+JSON.stringify(type)+');';document.head.append(s);
    }
    const lang=document.createElement('script');lang.setAttribute('language','javascript1.5');lang.text='console.log("language");';document.head.append(lang);
    const n=document.createElement('script');n.noModule=true;n.text='console.log("nomodule");';document.head.append(n);const copy=n.cloneNode(true);copy.noModule=false;document.body.append(copy);
    const m=document.createElement('script');m.type=' module ';m.text='console.log("module");';document.body.append(m);document.body.append(m.cloneNode(true));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["text/javascript1.5", "text/livescript", "application/x-javascript", " \ttext/javascript\r\n", "language", "module"]);
}

#[test]
fn adopting_a_prepared_script_into_another_document_cancels_its_execution_without_restarting_it() {
    let (_, report) = visit(
        r#"<script>
    window.foreign=new DOMParser().parseFromString('','text/html');
    const a=document.createElement('script'),b=document.createElement('script');window.second=b;
    a.text='console.log("first");foreign.body.append(second);';b.text='console.log("moved");';
    document.body.append(a,b);console.log('after');document.body.append(b);document.body.append(b.cloneNode(true));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["first", "after"]);
}

#[test]
fn an_empty_script_source_reports_error_asynchronously_and_keeps_clones_started() {
    let (r, report) = visit(
        r#"<script>
    const s=document.createElement('script');s.src='';s.addEventListener('error',()=>console.log('error'));
    document.body.append(s);s.removeAttribute('src');s.text='console.log("reran");';document.body.append(s.cloneNode(true));console.log('after');
    </script>"#,
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert!(paths.is_empty(), "{paths:?}");
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["after", "error"]);
}

#[test]
fn fragment_parsers_do_not_mark_scripts_created_by_custom_element_constructors_as_parser_created() {
    let (_, report) = visit(
        r#"<script>
    const other=new DOMParser().parseFromString('','text/html');
    customElements.define('x-build',class extends HTMLElement{constructor(){super();const s=other.createElement('script');s.text='console.log("fresh-constructor");';document.head.append(s);document.head.append(s.cloneNode(true));console.log('constructor-after');}});
    const holder=document.createElement('div');holder.innerHTML='<x-build></x-build><script>console.log("parsed");</'+'script>';
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["fresh-constructor", "constructor-after"]);
}

#[test]
fn fragment_tree_building_uses_table_and_svg_contexts_and_keeps_parsed_scripts_inert() {
    let (_, report) = visit(
        r#"<script>
    const table=document.createElement('table');table.innerHTML='<tr><td>cell</td></tr>';console.log(table.innerHTML);
    table.firstChild.insertAdjacentHTML('beforeend','<tr><td>second</td></tr>');console.log(table.rows?.length??table.querySelectorAll('tr').length);
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.innerHTML='<g><circle/></g><foreignObject><div>html</div></foreignObject><script>console.log("parsed");</'+'script>';
    console.log(svg.firstChild.namespaceURI,svg.firstChild.firstChild.namespaceURI,svg.children[1].firstChild.namespaceURI);document.body.append(svg);
    const range=document.createRange();range.selectNodeContents(table.firstChild);const fragment=range.createContextualFragment('<tr><td>range</td></tr>');console.log(fragment.firstChild.localName,fragment.firstChild.firstChild.localName);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        ["<tbody><tr><td>cell</td></tr></tbody>", "2", "http://www.w3.org/2000/svg http://www.w3.org/2000/svg http://www.w3.org/1999/xhtml", "tr td"]
    );
}

#[test]
fn markup_coercion_happens_once_and_its_fresh_scripts_execute_without_becoming_parsed_scripts() {
    let (_, report) = visit(
        r#"<script>
    let calls=0;const holder=document.createElement('div');holder.innerHTML={toString(){calls++;const s=document.createElement('script');s.text='console.log("coercion");';document.head.append(s);document.head.append(s.cloneNode(true));return '<script>console.log("parsed");</'+'script>';}};
    console.log('after',calls);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["coercion", "after 1"]);
}

#[test]
fn script_preparation_uses_real_attributes_and_child_text_despite_public_accessor_overrides() {
    let (_, report) = visit(
        r#"<script>
    const s=document.createElement('script');s.text='console.log("real");';s.getAttribute=()=>null;s.hasAttribute=()=>false;Object.defineProperty(s,'textContent',{value:''});document.head.append(s);
    const n=document.createElement('script');n.noModule=true;n.text='console.log("nomodule");';n.getAttribute=()=>null;n.hasAttribute=()=>false;document.head.append(n);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["real"]);
}

#[test]
fn public_document_type_and_script_owner_shadows_do_not_change_preparation_or_execution() {
    let (_, report) = visit(
        r#"<script>
    window.inertDoc=new DOMParser().parseFromString('','text/html');
    const a=document.createElement('script'),b=document.createElement('script');window.second=b;
    a.text='Object.defineProperty(second,"ownerDocument",{value:inertDoc});console.log("first");';b.text='console.log("second");';document.body.append(a,b);
    Object.defineProperty(document,'nodeType',{value:1});const s=document.createElement('script');s.text='console.log("real-document");';document.head.append(s);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["first", "second", "real-document"]);
}

#[test]
fn template_cloning_copies_nested_contents_only_when_deep_and_keeps_them_independent() {
    let (_, report) = visit(
        r#"<template id=t data-x=a>start<!--c--><p data-p=v>text</p><template id=n><b>nested</b></template></template><script>
    const t=document.getElementById('t');
    for(const deep of [false,true]){const copy=t.cloneNode(deep);console.log(deep,copy.childNodes.length,copy.content.childNodes.length,copy.getAttribute('data-x'),copy.content.querySelector('#n')?.content.textContent||'');}
    const copy=t.cloneNode(true),p=copy.content.querySelector('p');if(p){p.textContent='changed';p.setAttribute('data-p','changed');}console.log(t.content.querySelector('p').textContent,t.content.querySelector('p').getAttribute('data-p'));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["false 0 0 a ", "true 0 4 a nested", "text v"]);
}

#[test]
fn template_light_children_and_contents_remain_separate_when_read_cloned_and_inserted() {
    let (_, report) = visit(
        r#"<script>
    const t=document.createElement('template'),light=document.createElement('i');light.textContent='light';t.append(light);
    console.log(t.childNodes.length,t.content.childNodes.length);t.innerHTML='<b>content</b>';const content=t.content;
    const copy=t.cloneNode(true);console.log(copy.childNodes.length,copy.content.childNodes.length,copy.firstChild?.textContent,copy.content.firstChild?.textContent,copy.content===copy.content);
    document.body.append(content);console.log(t.childNodes.length,t.firstChild===light,content.childNodes.length,content===t.content);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["1 0", "1 1 light content true", "1 true 0 true"]);
}

#[test]
fn template_contents_use_a_shared_inert_document_and_document_clones_get_their_own() {
    let (_, report) = visit(
        r#"<template id=t><p data-p=v>text</p><template id=n><i>nested</i></template></template><script>
    const t=document.getElementById('t'),owner=t.content.ownerDocument,n=t.content.querySelector('#n');
    console.log(owner!==document,owner===document.createElement('template').content.ownerDocument,owner===n.content.ownerDocument,t.content.firstChild.ownerDocument===owner,t.content.firstChild.attributes[0].ownerDocument===owner,owner.documentElement===null,owner.defaultView===null,owner.compatMode);
    const copy=document.cloneNode(true),tc=copy.getElementById('t');console.log(tc.content.childNodes.length,tc.content.ownerDocument!==owner,tc.content.ownerDocument!==copy,tc.content.ownerDocument===copy.createElement('template').content.ownerDocument,tc.content.querySelector('#n')?.content.ownerDocument===tc.content.ownerDocument);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["true true true true true true true CSS1Compat", "2 true true true true"]);
}

#[test]
fn cloned_template_contents_preserve_script_preparation_state() {
    let (r, report) = visit(
        r#"<template id=t><script>fetch('/template-ran');</script></template><script>
    const t=document.getElementById('t'),copy=t.cloneNode(true);document.body.append(copy);console.log('connected-template');document.body.append(copy.content);
    const parsed=new DOMParser().parseFromString('<template><script>fetch("/parsed-reran");</'+'script></template>','text/html');document.body.append(parsed.querySelector('template').cloneNode(true).content);
    const ran=document.createElement('script');ran.text='console.log("ran");';document.body.append(ran);const saved=document.createElement('template');saved.content.append(ran);document.body.append(saved.cloneNode(true).content);
    </script>"#,
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/template-ran"]);
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["connected-template", "ran"]);
}

#[test]
fn template_contents_survive_cloning_through_elements_fragments_and_documents() {
    for kind in ["element", "fragment", "document"] {
        let html = format!(
            r#"<section id=source><template><span>outer</span><template><em>inner</em></template></template></section><script>
        const section=document.getElementById('source');let copy;
        if('{kind}'==='element')copy=section.cloneNode(true);else if('{kind}'==='document')copy=document.cloneNode(true).getElementById('source');else{{const fragment=document.createDocumentFragment();fragment.append(section);copy=fragment.cloneNode(true);}}
        const t=copy.querySelector('template');console.log(t.content.childNodes.length,t.content.querySelector('span')?.textContent||'',t.content.querySelector('template')?.content.textContent||'');
        </script>"#
        );
        let (_, report) = visit(&html);
        assert_eq!(report["console"][0]["text"], "2 outer inner", "{kind}");
    }
}

#[test]
fn template_parsing_and_cloning_delay_custom_element_construction_until_insertion() {
    let (_, report) = visit(
        r#"<template id=t><x-probe data-a=v></x-probe></template><script>
    let constructed=0;customElements.define('x-probe',class extends HTMLElement{constructor(){super();constructed++;}connectedCallback(){console.log('connected');}});
    const t=document.getElementById('t'),copy=t.cloneNode(true);console.log('cloned',constructed,copy.content.childNodes.length);document.body.append(copy.content);console.log('inserted',constructed);
    const fresh=document.createElement('template');fresh.innerHTML='<x-probe></x-probe>';console.log('parsed',constructed);const fragment=fresh.content.cloneNode(true);console.log('content-cloned',constructed);document.body.append(fragment);console.log('content-inserted',constructed);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["cloned 0 1", "connected", "inserted 1", "parsed 1", "content-cloned 1", "connected", "content-inserted 2"]);
}

#[test]
fn upgrading_inserted_template_contents_preserves_attributes_and_only_reports_real_mutations() {
    let (_, report) = visit(
        r#"<template id=t><x-probe data-a=v></x-probe></template><script>
    customElements.define('x-probe',class extends HTMLElement{static observedAttributes=['data-a'];constructor(){super();console.log('constructor',this.isConnected,this.getAttribute('data-a'));this.setAttribute('data-a','changed');}attributeChangedCallback(name,oldValue,value){console.log('attribute',name,oldValue,value);}connectedCallback(){console.log('connected');}});
    const copy=document.getElementById('t').cloneNode(true),child=copy.content.firstChild;
    if(child){const observer=new MutationObserver(()=>{});observer.observe(child,{attributes:true});document.body.append(copy.content);console.log('records',observer.takeRecords().map(r=>r.type+':'+r.attributeName).join(','));observer.disconnect();}
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["constructor true v", "attribute data-a null v", "connected", "records attributes:data-a"]);
}

#[test]
fn template_serialization_includes_nested_contents_without_copying_its_light_children_or_running_code() {
    let (r, report) = visit(
        r#"<div id=holder><template id=t><p>outer</p><template><b>inner</b></template></template></div><script>
    const t=document.getElementById('t'),light=document.createElement('i');light.textContent='light';t.append(light);
    console.log(t.innerHTML);console.log(t.outerHTML);console.log(document.getElementById('holder').innerHTML);console.log(t.cloneNode(true).innerHTML);
    const fresh=document.createElement('template');fresh.innerHTML='<script>fetch("/serialized");</'+'script>';console.log(fresh.innerHTML.includes('fetch'));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "<p>outer</p><template><b>inner</b></template>",
            "<template id=\"t\"><p>outer</p><template><b>inner</b></template></template>",
            "<template id=\"t\"><p>outer</p><template><b>inner</b></template></template>",
            "<p>outer</p><template><b>inner</b></template>",
            "true"
        ]
    );
    assert!(r.events.iter().all(|e| e.func != FETCH_OWN));
}

// HTML's template adopting steps retarget contents to the destination's
// associated inert document, including nested templates and attributes.
#[test]
fn adopting_templates_retargets_nested_contents_to_the_destinations_inert_document() {
    let (_, report) = visit(
        r#"<script>
    const foreign=new DOMParser().parseFromString('<template id=t><template><p data-p=v>text</p></template></template>','text/html');
    const t=foreign.getElementById('t'),old=t.content.ownerDocument,content=t.content,nested=content.firstChild;
    const expected=document.createElement('template').content.ownerDocument,light=foreign.createElement('i');light.textContent='light';t.append(light);document.body.append(t);
    console.log(t.ownerDocument===document,light.ownerDocument===document,content===t.content,content.ownerDocument===expected,content.ownerDocument!==old,nested.ownerDocument===expected,nested.content.ownerDocument===expected,nested.content.firstChild.attributes[0].ownerDocument===expected);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "true true true true true true true true");
}

#[test]
fn cloning_and_serializing_templates_do_not_consult_public_content_getters() {
    let (_, report) = visit(
        r#"<template id=t><span>real</span></template><script>
    const t=document.getElementById('t');let reads=0;Object.defineProperty(t,'content',{get(){reads++;throw Error('page getter');}});
    const copy=t.cloneNode(true);console.log(reads,copy.content.childNodes.length,copy.content.textContent,t.innerHTML);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "0 1 real <span>real</span>");
}

#[test]
fn template_upgrade_callbacks_run_fresh_inline_scripts_before_the_callback_returns() {
    let (r, report) = visit(
        r#"<template id=t><x-script></x-script></template><script>
    customElements.define('x-script',class extends HTMLElement{constructor(){super();const s=document.createElement('script');s.text='console.log("constructor-script");fetch("/constructor");';document.head.append(s);document.head.append(s.cloneNode(true));console.log('constructor-after');}connectedCallback(){const s=document.createElement('script');s.text='console.log("connected-script");';document.head.append(s);console.log('connected-after');}});
    document.body.append(document.getElementById('t').cloneNode(true).content);console.log('inserted');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["constructor-script", "constructor-after", "connected-script", "connected-after", "inserted"]);
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/constructor"]);
}

#[test]
fn deeply_nested_template_contents_clone_without_losing_inner_trees() {
    let (_, report) = visit(
        r#"<script>
    const root=document.createElement('template');let current=root;
    for(let i=0;i<500;i++){const next=document.createElement('template');current.content.append(next);current=next;}
    current.content.append('leaf');const copy=root.cloneNode(true);let count=0,node=copy;
    while(node.content.firstChild instanceof HTMLTemplateElement){count++;node=node.content.firstChild;}
    console.log(count,node.content.textContent,copy.content.ownerDocument===node.content.ownerDocument);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "500 leaf true");
}

#[test]
fn failed_template_custom_element_upgrades_report_once_and_do_not_throw_from_insertion() {
    let (_, report) = visit_unchecked(
        r#"<template id=t><x-fail></x-fail></template><script>
    customElements.define('x-fail',class extends HTMLElement{constructor(){super();console.log('constructor');throw Error('upgrade failed');}connectedCallback(){console.log('connected');}});
    const fragment=document.getElementById('t').cloneNode(true).content,child=fragment.firstChild;
    document.body.append(fragment);console.log('returned');child.remove();document.body.append(child);console.log('reinserted');
    </script>"#,
        json!({}),
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["constructor", "returned", "reinserted"]);
    assert_eq!(report["errors"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["errors"][0]["message"], "upgrade failed");
}

#[test]
fn queries_include_template_light_children_but_do_not_enter_template_contents() {
    let (_, report) = visit(
        r#"<template id=t><b id=inert>content</b></template><script>
    const t=document.getElementById('t'),light=document.createElement('i');light.id='light';t.append(light);
    console.log(t.querySelector('#light')===light,document.querySelector('#light')===light,document.querySelectorAll('template i').length,document.querySelector('#inert')===null,t.content.querySelector('#inert')?.textContent);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "true true 1 true content");
}

#[test]
fn svg_elements_named_template_do_not_hide_executable_scripts() {
    let (r, _) =
        visit(r#"<svg><template><script>fetch('/svg-template');</script></template></svg><template><script>fetch('/html-template');</script></template>"#);
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/svg-template"]);
}

#[test]
fn html_templates_in_xml_documents_keep_xml_inert_owners_and_clone_their_contents() {
    let (_, report) = visit(
        r#"<script>
    const xml=new DOMParser().parseFromString('<root/>','text/xml'),t=xml.createElementNS('http://www.w3.org/1999/xhtml','h:template'),owner=t.content.ownerDocument;
    t.innerHTML='<child data-x="v">text</child>';const source=t.content.firstChild;console.log('source',source.ownerDocument===owner,source.attributes[0].ownerDocument===owner);const copy=t.cloneNode(true),child=copy.content.firstChild;
    console.log(owner!==xml,owner.contentType,owner.defaultView===null,owner===xml.createElementNS('http://www.w3.org/1999/xhtml','template').content.ownerDocument,t.childNodes.length,copy.content.childNodes.length,child?.namespaceURI,child?.ownerDocument===owner,child?.attributes[0].ownerDocument===owner,copy.prefix,copy.localName);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "source true true");
    assert_eq!(report["console"][1]["text"], "true application/xml true true 0 1 null true true h template");
}

#[test]
fn cloned_template_contents_keep_svg_owners_namespaces_and_executable_script_identity() {
    for kind in ["template", "document"] {
        let html = format!(
            r#"<template id=t><svg><g><circle/></g><script>fetch('/svg-cloned');</script></svg><math><script>fetch('/math-cloned');</script></math></template><script>
        const original=document.getElementById('t'),copy='{kind}'==='template'?original.cloneNode(true):document.cloneNode(true).getElementById('t'),svg=copy.content.firstChild,g=svg.firstChild;
        console.log(svg.ownerSVGElement,g.ownerSVGElement===svg,g.firstChild.ownerSVGElement===svg,svg.lastChild.ownerSVGElement===svg,copy.content.lastChild.namespaceURI);
        document.body.append(copy.content);
        </script>"#
        );
        let (r, report) = visit(&html);
        assert_eq!(report["console"][0]["text"], "null true true true http://www.w3.org/1998/Math/MathML", "{kind}");
        let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["/svg-cloned"], "{kind}");
    }
}

#[test]
fn imported_subtrees_belong_to_the_destination_before_insertion() {
    let (_, report) = visit(
        r#"<script>
    const foreign=new DOMParser().parseFromString('<section data-a=v><span data-b=w>text<!--c--></span><template><i data-c=x>nested</i></template></section>','text/html'),source=foreign.querySelector('section');
    for(const deep of [false,true]){const copy=document.importNode(source,deep);console.log(deep,copy.ownerDocument===document,copy.attributes[0].ownerDocument===document,copy.childNodes.length,deep?copy.firstChild.firstChild.ownerDocument===document:true,deep?copy.firstChild.lastChild.ownerDocument===document:true,deep?copy.firstChild.attributes[0].ownerDocument===document:true,deep?copy.querySelector('template').content.ownerDocument===document.createElement('template').content.ownerDocument:true);}
    console.log(source.ownerDocument===foreign,source.parentNode!==null,source.attributes[0].ownerDocument===foreign);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["false true true 0 true true true true", "true true true 2 true true true true", "true true true"]);
}

#[test]
fn importing_fragments_and_plain_nodes_preserves_types_values_and_source_ownership() {
    let (_, report) = visit(
        r#"<script>
    const foreign=new DOMParser().parseFromString('<p data-a=v>text<!--c--></p>','text/html'),p=foreign.querySelector('p'),f=foreign.createDocumentFragment();f.append(p);
    const copy=document.importNode(f,true);console.log(copy.ownerDocument===document,copy.firstChild.ownerDocument===document,copy.firstChild.attributes[0].ownerDocument===document,copy.firstChild.firstChild.ownerDocument===document,f.childNodes.length);
    for(const source of [p.attributes[0],p.firstChild,p.lastChild,foreign.createDocumentType('html')]){const n=document.importNode(source);console.log(n.nodeType,n.ownerDocument===document,n.ownerElement??n.parentNode,n.value??n.nodeValue??n.name,source.ownerDocument===foreign);}
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["true true true true 1", "2 true null v true", "3 true null text true", "8 true null c true", "10 true null html true"]);
}

#[test]
fn imported_custom_elements_construct_with_the_completed_copy_and_destination_registry() {
    let (_, report) = visit(
        r#"<script>
    const foreign=new DOMParser().parseFromString('','text/html');
    customElements.define('x-import',class extends HTMLElement{constructor(){super();console.log('constructor',this.getAttribute('data-a'),this.childNodes.length,this.ownerDocument===document,this.isConnected);}static observedAttributes=['data-a'];attributeChangedCallback(name,oldValue,value){console.log('attribute',name,oldValue,value);}adoptedCallback(){console.log('adopted');}connectedCallback(){console.log('connected');}});
    const source=foreign.createElement('x-import');source.setAttribute('data-a','v');source.append(foreign.createElement('b'));const copy=document.importNode(source,true);console.log('imported',copy instanceof customElements.get('x-import'));
    const inert=foreign.importNode(copy,true);console.log('inert',inert instanceof customElements.get('x-import'),inert.ownerDocument===foreign);const cloned=copy.cloneNode(true);console.log('cloned',cloned instanceof customElements.get('x-import'));document.body.append(copy);console.log('inserted');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "constructor v 1 true false",
            "attribute data-a null v",
            "imported true",
            "inert false true",
            "constructor v 1 true false",
            "attribute data-a null v",
            "cloned true",
            "connected",
            "inserted"
        ]
    );
}

#[test]
fn import_does_not_use_the_sources_public_clone_method_or_adopt_its_original_nodes() {
    let (_, report) = visit(
        r#"<script>
    const other=new DOMParser().parseFromString('<p data-a=v>real</p>','text/html'),source=other.querySelector('p');let calls=0;
    Object.defineProperty(source,'cloneNode',{get(){calls++;throw Error('page clone getter');}});
    const n=document.importNode(source,true);console.log(calls,n.localName,n.textContent,n.ownerDocument===document,n.attributes[0].ownerDocument===document,source.ownerDocument===other,source.parentNode===other.body);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "0 p real true true true true");
}

#[test]
fn import_rejects_documents_shadow_roots_and_non_nodes_without_calling_guest_methods() {
    let (_, report) = visit(
        r#"<script>
    const shadow=document.createElement('div').attachShadow({mode:'open'});let calls=0;
    for(const n of [document,shadow]){Object.defineProperty(n,'cloneNode',{get(){calls++;throw Error('page getter');}});Object.defineProperty(n,'nodeType',{value:1});try{document.importNode(n,true);console.log('accepted');}catch(e){console.log(e.name);}}
    for(const n of [null,{},'text']){try{document.importNode(n,true);console.log('accepted');}catch(e){console.log(e.name);}}
    try{document.importNode();}catch(e){console.log(e.name);}console.log('calls',calls,document.importNode.length);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["NotSupportedError", "NotSupportedError", "TypeError", "TypeError", "TypeError", "TypeError", "calls 0 1"]);
}

#[test]
fn imported_scripts_keep_their_preparation_state_while_fresh_scripts_execute_after_insertion() {
    let (r, report) = visit(
        r#"<script id=ran>console.log('original');</script><script>
    document.body.append(document.importNode(document.getElementById('ran'),true));
    const other=new DOMParser().parseFromString('<script>fetch("/parsed-reran");</'+'script>','text/html');document.body.append(document.importNode(other.querySelector('script'),true));
    const fresh=other.createElement('script');fresh.text='fetch("/fresh-import");';const copy=document.importNode(fresh,true);console.log(copy.ownerDocument===document,copy.firstChild.ownerDocument===document);document.body.append(copy);
    </script>"#,
    );
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/fresh-import"]);
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["original", "true true"]);
}

#[test]
fn import_options_follow_boolean_and_dictionary_semantics_and_validate_registries() {
    let (_, report) = visit(
        r#"<script>
    const source=document.createElement('div');source.append(document.createElement('b'));
    for(const [name,value] of [['default',undefined],['false',false],['true',true],['null',null],['empty',{}],['self',{selfOnly:true}],['deep',{selfOnly:false}],['zero',0],['one',1]])console.log(name,document.importNode(source,value).childNodes.length);
    const order=[];console.log('options',document.importNode(source,{get customElementRegistry(){order.push('registry');return customElements;},get selfOnly(){order.push('self');return true;}}).childNodes.length,order.join(','));
    try{document.importNode(source,{customElementRegistry:{}});}catch(e){console.log(e.name);}
    const other=new DOMParser().parseFromString('','text/html');try{other.importNode(source,{customElementRegistry:customElements});}catch(e){console.log(e.name);}
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "default 0",
            "false 0",
            "true 1",
            "null 1",
            "empty 1",
            "self 0",
            "deep 1",
            "zero 0",
            "one 1",
            "options 0 registry,self",
            "TypeError",
            "NotSupportedError"
        ]
    );
}

#[test]
fn import_ignores_frozen_descendant_clone_methods_and_destination_factory_overrides() {
    let (_, report) = visit(
        r#"<script>
    const other=new DOMParser().parseFromString('<div data-a=v><span>text<!--c--></span></div>','text/html'),source=other.querySelector('div');let calls=0;
    const bad=()=>{calls++;throw Error('page method');};
    for(const node of [source.attributes[0],source.firstChild.firstChild,source.firstChild.lastChild])Object.defineProperty(node,'cloneNode',{value:bad});
    Object.defineProperty(source.firstChild,'localName',{get:bad});
    Object.defineProperty(document,'createElement',{value:bad});Object.defineProperty(document,'createElementNS',{value:bad});
    const copy=document.importNode(source,true);console.log(calls,copy.localName,copy.firstChild.localName,copy.textContent,copy.attributes[0].value);
    </script>"#,
    );
    assert_eq!(report["console"][0]["text"], "0 div span text v");
}

#[test]
fn importing_template_contents_upgrades_only_the_copies_in_the_destination_document() {
    let (_, report) = visit(
        r#"<template id=t><x-import data-a=v><b>text</b></x-import><template><x-import></x-import></template></template><script>
    let count=0;customElements.define('x-import',class extends HTMLElement{constructor(){super();count++;console.log('constructor',this.getAttribute('data-a'),this.childNodes.length,this.isConnected);}adoptedCallback(){console.log('adopted');}});
    const t=document.getElementById('t'),copy=document.importNode(t.content,true);console.log('import',count,copy.firstChild.ownerDocument===document,copy.firstChild.attributes[0].ownerDocument===document,copy.lastChild.content.ownerDocument!==document,t.content.firstChild instanceof customElements.get('x-import'));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["constructor v 1 false", "import 1 true true true false"]);
}

#[test]
fn custom_element_attributes_and_children_can_drive_behavior_during_import_construction() {
    let (r, report) = visit(
        r#"<script>
    customElements.define('x-effect',class extends HTMLElement{constructor(){super();const s=document.createElement('script');s.text='console.log("inline");';document.head.append(s);document.head.append(s.cloneNode(true));if(this.getAttribute('data-run')==='yes'&&this.firstChild?.textContent==='ready')fetch('/import-constructor');console.log('constructor-after');}});
    const other=new DOMParser().parseFromString('<x-effect data-run=yes><b>ready</b></x-effect>','text/html');document.importNode(other.body.firstChild,true);console.log('returned');
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["inline", "constructor-after", "returned"]);
    let paths: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN).map(|e| e.args["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/import-constructor"]);
}

#[test]
fn queued_import_upgrades_keep_their_definition_when_a_parent_constructor_moves_the_child() {
    let (_, report) = visit(
        r#"<script>
    window.other=new DOMParser().parseFromString('<x-parent><x-child data-a=v></x-child></x-parent>','text/html');
    customElements.define('x-child',class extends HTMLElement{constructor(){super();console.log('child',this.ownerDocument===other,this.getAttribute('data-a'));}connectedCallback(){console.log('connected',this.ownerDocument===other);}});
    customElements.define('x-parent',class extends HTMLElement{constructor(){super();window.moved=this.firstChild;other.body.append(moved);console.log('parent');}});
    const copy=document.importNode(other.querySelector('x-parent'),true);console.log('returned',copy.childNodes.length,moved instanceof customElements.get('x-child'));
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["parent", "child true v", "connected true", "returned 0 true"]);
}

#[test]
fn nested_import_before_super_does_not_consume_an_outer_upgrade_construction_token() {
    let (_, report) = visit(
        r#"<script>
    window.other=new DOMParser().parseFromString('<x-parent data-a=v></x-parent>','text/html');
    customElements.define('x-parent',class extends HTMLElement{constructor(){const n=document.importNode(other.createElement('b'));super();console.log(n.localName,n.ownerDocument===document,this.localName,this.getAttribute('data-a'));}});
    const copy=document.importNode(other.body.firstChild,true);console.log(copy.localName,copy.ownerDocument===document);
    </script>"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["b true x-parent v", "x-parent true"]);
}

#[test]
fn failed_import_constructors_do_not_throw_from_import_or_cancel_later_child_upgrades() {
    let (_, report) = visit_unchecked(
        r#"<script>
    customElements.define('x-parent',class extends HTMLElement{constructor(){super();console.log('parent');throw Error('import failed');}connectedCallback(){console.log('failed-connected');}});
    customElements.define('x-child',class extends HTMLElement{constructor(){super();console.log('child',this.ownerDocument===document,this.isConnected);}connectedCallback(){console.log('child-connected');}});
    const other=new DOMParser().parseFromString('<x-parent><x-child></x-child></x-parent>','text/html');const copy=document.importNode(other.body.firstChild,true);console.log('returned',copy.firstChild instanceof customElements.get('x-child'));document.body.append(copy);
    </script>"#,
        json!({}),
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(logs, ["parent", "child true false", "returned true", "child-connected"]);
    assert_eq!(report["errors"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["errors"][0]["message"], "import failed");
}
