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
