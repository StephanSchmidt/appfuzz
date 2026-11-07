//! HTML read the way a browser reads it: the WHATWG parser (html5ever) with
//! scripting on. `<noscript>`, SVG and MathML content, unquoted attributes,
//! comments and raw text come out as a browser builds them, so markup a
//! browser runs can't hide from the checks, and inert text isn't reported.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::{Rc, Weak};
use std::sync::LazyLock;

use html5ever::interface::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tree_builder::TreeBuilderOpts;
use html5ever::{Attribute, ParseOpts, QualName, parse_document};
use regex::Regex;

/// One element as the browser sees it: attributes in order, entities
/// decoded, names in lower case.
pub(crate) struct Element {
    pub name: String,
    namespace: Namespace,
    pub attrs: Vec<(String, String)>,
    /// The start tag rebuilt from the element, at most 160 characters.
    pub raw: String,
    /// The text of a `script` or `style` element.
    pub body: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Html,
    Svg,
    Other,
    /// The bounded fallback cannot reconstruct namespaces; keep its
    /// conservative interpretation of every potentially active tag.
    Unknown,
}

impl Element {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    pub fn is_html(&self) -> bool {
        matches!(self.namespace, Namespace::Html | Namespace::Unknown)
    }

    pub fn is_script(&self) -> bool {
        self.name == "script" && self.namespace != Namespace::Other
    }

    pub fn script_sources(&self) -> impl Iterator<Item = &str> {
        let urls = if !self.is_script() {
            [None; 3]
        } else {
            match self.namespace {
                Namespace::Svg => [self.get("href").or_else(|| self.get("xlink:href")), None, None],
                Namespace::Html => [self.get("src"), None, None],
                Namespace::Unknown => [self.get("src"), self.get("href"), self.get("xlink:href")],
                Namespace::Other => [None; 3],
            }
        };
        urls.into_iter().flatten()
    }

    pub fn is_inline_script(&self) -> bool {
        self.is_script() && (self.namespace == Namespace::Unknown || self.script_sources().next().is_none())
    }

    pub fn script_source_attribute(&self, attr: &str) -> bool {
        self.is_script()
            && match self.namespace {
                Namespace::Svg => attr == "href" || (attr == "xlink:href" && self.get("href").is_none()),
                Namespace::Html => attr == "src",
                Namespace::Unknown => matches!(attr, "src" | "href" | "xlink:href"),
                Namespace::Other => false,
            }
    }
}

/// A parsed piece of markup.
pub(crate) struct Doc {
    /// Elements in document order, template contents included.
    pub elements: Vec<Element>,
    /// Text outside scripts and styles, and comments, separated by spaces.
    pub text: String,
}

thread_local! {
    // The last markup parsed on this thread: several checks of one run read
    // the same body. Keyed by content, so it is never stale.
    static DOC: RefCell<(String, Rc<Doc>)> = RefCell::new((String::new(), Rc::new(Doc { elements: vec![], text: String::new() })));
}

/// Looks up `html` in a one-entry cache, or computes and keeps it.
pub(crate) fn memo<T>(cache: &'static std::thread::LocalKey<RefCell<(String, Rc<T>)>>, html: &str, f: impl FnOnce(&str) -> T) -> Rc<T> {
    if let Some(v) = cache.with_borrow(|(k, v)| (k == html).then(|| v.clone())) {
        return v;
    }
    let v = Rc::new(f(html));
    cache.set((html.to_string(), v.clone()));
    v
}

/// The markup parsed, once per thread and text.
pub(crate) fn doc(html: &str) -> Rc<Doc> {
    memo(&DOC, html, parse)
}

/// Table parts at the start of a fragment: a browser keeps them only inside
/// a table, so the fragment is read as the inside of one.
const TABLE_PARTS: &[&str] = &["<tr", "<td", "<th", "<tbody", "<thead", "<tfoot", "<caption", "<col", "<colgroup"];

/// Nesting the parser handles quickly: its scope checks walk the open
/// elements, so time grows with the square of the depth. Browsers stop
/// nesting at 512.
const MAX_DEPTH: usize = 1000;

/// Elements that never nest, or end where the next one of their kind starts.
const FLAT: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "param", "keygen", "p", "li", "dt", "dd", "option",
    "optgroup", "tr", "td", "th", "tbody", "thead", "tfoot", "colgroup", "caption", "rt", "rp", "html", "head", "body",
];

/// An upper bound on how deep the parser will nest elements: start tags
/// push, an end tag pops only when it names the innermost open element.
/// Raw text (script, style, textarea, title) is skipped.
fn depth(html: &str) -> usize {
    let b = html.as_bytes();
    let (mut open, mut max): (Vec<&[u8]>, usize) = (Vec::new(), 0);
    let mut i = 0;
    while let Some(j) = memchr::memchr(b'<', &b[i..]) {
        i += j + 1;
        let end = b.get(i) == Some(&b'/');
        let s = i + usize::from(end);
        let n = b[s..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'-').count();
        if n == 0 || !b[s].is_ascii_alphabetic() {
            continue;
        }
        let name = &b[s..s + n];
        if end {
            if open.last().is_some_and(|o| o.eq_ignore_ascii_case(name)) {
                open.pop();
            }
        } else if let Some(raw) = ["script", "style", "textarea", "title", "xmp", "plaintext"].iter().find(|r| name.eq_ignore_ascii_case(r.as_bytes())) {
            let close = format!("</{raw}");
            let rest = &html[s + n..];
            match rest.as_bytes().windows(close.len()).position(|w| w.eq_ignore_ascii_case(close.as_bytes())) {
                Some(k) => i = s + n + k + close.len(),
                None => break,
            }
        } else if !FLAT.iter().any(|f| name.eq_ignore_ascii_case(f.as_bytes())) {
            open.push(name);
            max = max.max(open.len());
        }
    }
    max
}

fn parse(html: &str) -> Doc {
    if depth(html) > MAX_DEPTH {
        return read_tags(html);
    }
    let t = html.trim_start();
    let table_part = TABLE_PARTS.iter().any(|p| {
        t.get(..p.len()).is_some_and(|s| s.eq_ignore_ascii_case(p)) && t[p.len()..].starts_with(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
    });
    let input = if table_part { format!("<table>{html}") } else { html.to_string() };
    let opts = ParseOpts { tree_builder: TreeBuilderOpts { scripting_enabled: true, ..Default::default() }, ..Default::default() };
    let root = parse_document(Sink { document: Node::new(Data::Document) }, opts).one(StrTendril::from(input));
    flatten(&root)
}

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([a-zA-Z][a-zA-Z0-9-]*)\b((?:[^>\x22']|\x22[^\x22]*\x22|'[^']*')*)>").unwrap());
static ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([a-zA-Z_:@(\[#*][-a-zA-Z0-9_:.@()\[\]#*]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?"#).unwrap());
static BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<(script|style)\b([^>]*)>(.*?)</(?:script|style)\s*>").unwrap());

/// Markup too deep to parse quickly, read tag by tag: every start tag
/// counts, inert ones too, so nothing a browser would run is missed.
fn read_tags(html: &str) -> Doc {
    let mut bodies = BLOCK.captures_iter(html).map(|c| c[3].to_string());
    let flat = BLOCK.replace_all(html, |c: &regex::Captures| format!("<{}{}>", &c[1], &c[2]));
    let elements = TAG
        .captures_iter(&flat)
        .map(|t| {
            let mut attrs: Vec<(String, String)> = Vec::new();
            for a in ATTR.captures_iter(&t[2]) {
                let k = a[1].to_ascii_lowercase();
                let v = a.get(2).or(a.get(3)).or(a.get(4)).map(|m| m.as_str()).unwrap_or_default();
                if !attrs.iter().any(|(n, _)| *n == k) {
                    attrs.push((k, crate::urls::decode_entities(v)));
                }
            }
            let name = t[1].to_ascii_lowercase();
            let body = if name == "script" || name == "style" { bodies.next() } else { None };
            Element { name, namespace: Namespace::Unknown, attrs, raw: t[0].chars().take(160).collect(), body }
        })
        .collect();
    let text = crate::urls::decode_entities(&TAG.replace_all(&BLOCK.replace_all(html, " "), " "));
    Doc { elements, text }
}

/// The tree in document order. Iterative: hostile markup nests deeply.
fn flatten(root: &Handle) -> Doc {
    let mut doc = Doc { elements: Vec::new(), text: String::new() };
    // (node, inside a script or style)
    let mut stack: Vec<(Handle, bool)> = vec![(root.clone(), false)];
    while let Some((n, raw)) = stack.pop() {
        match &n.data {
            Data::Element { name, attrs, template, .. } => {
                let local = str::to_ascii_lowercase(&name.local);
                let namespace = match name.ns.as_ref() {
                    "http://www.w3.org/1999/xhtml" => Namespace::Html,
                    "http://www.w3.org/2000/svg" => Namespace::Svg,
                    _ => Namespace::Other,
                };
                let attrs: Vec<(String, String)> = attrs.borrow().iter().map(|a| (attr_name(&a.name), a.value.to_string())).collect();
                let is_body = matches!(local.as_str(), "script" | "style") && namespace != Namespace::Other;
                let body = is_body.then(|| {
                    n.children.borrow().iter().filter_map(|c| if let Data::Text(t) = &c.data { Some(t.borrow().to_string()) } else { None }).collect()
                });
                doc.elements.push(Element { raw: start_tag(&local, &attrs), name: local, namespace, attrs, body });
                if let Some(t) = template {
                    stack.push((t.clone(), false));
                }
                stack.extend(n.children.borrow().iter().rev().map(|c| (c.clone(), is_body)));
            }
            Data::Text(t) if !raw => {
                doc.text.push_str(&t.borrow());
                doc.text.push(' ');
            }
            Data::Comment(t) => {
                doc.text.push_str(t);
                doc.text.push(' ');
            }
            _ => stack.extend(n.children.borrow().iter().rev().map(|c| (c.clone(), raw))),
        }
    }
    doc
}

/// `xlink:href` for a prefixed name, the local name otherwise.
fn attr_name(n: &QualName) -> String {
    match &n.prefix {
        Some(p) => format!("{p}:{}", n.local).to_ascii_lowercase(),
        None => str::to_ascii_lowercase(&n.local),
    }
}

fn start_tag(name: &str, attrs: &[(String, String)]) -> String {
    let mut s = format!("<{name}");
    for (k, v) in attrs {
        s.push(' ');
        s.push_str(k);
        if !v.is_empty() {
            s.push_str("=\"");
            s.push_str(v);
            s.push('"');
        }
    }
    s.push('>');
    s.chars().take(160).collect()
}

type Handle = Rc<Node>;

struct Node {
    data: Data,
    parent: RefCell<Weak<Node>>,
    children: RefCell<Vec<Handle>>,
}

enum Data {
    Document,
    /// A doctype or a processing instruction.
    Other,
    Text(RefCell<StrTendril>),
    Comment(StrTendril),
    Element {
        name: QualName,
        attrs: RefCell<Vec<Attribute>>,
        template: Option<Handle>,
        mathml_integration_point: bool,
    },
}

impl Node {
    fn new(data: Data) -> Handle {
        Rc::new(Node { data, parent: RefCell::new(Weak::new()), children: RefCell::default() })
    }
}

impl Drop for Node {
    // Iterative: a recursive drop overflows the stack on deep markup.
    fn drop(&mut self) {
        let mut nodes = std::mem::take(&mut *self.children.borrow_mut());
        if let Data::Element { template: Some(t), .. } = &self.data {
            nodes.push(t.clone());
        }
        while let Some(n) = nodes.pop() {
            nodes.append(&mut n.children.borrow_mut());
            if let Data::Element { template: Some(t), .. } = &n.data {
                nodes.append(&mut t.children.borrow_mut());
            }
        }
    }
}

fn detach(n: &Handle) {
    if let Some(p) = n.parent.replace(Weak::new()).upgrade() {
        p.children.borrow_mut().retain(|c| !Rc::ptr_eq(c, n));
    }
}

fn append_node(parent: &Handle, child: Handle) {
    detach(&child);
    *child.parent.borrow_mut() = Rc::downgrade(parent);
    parent.children.borrow_mut().push(child);
}

/// Appends text to a text node, if `n` is one.
fn merge_text(n: Option<&Handle>, t: &StrTendril) -> bool {
    match n.map(|n| &n.data) {
        Some(Data::Text(s)) => {
            s.borrow_mut().push_tendril(t);
            true
        }
        _ => false,
    }
}

struct Sink {
    document: Handle,
}

impl TreeSink for Sink {
    type Handle = Handle;
    type Output = Handle;
    type ElemName<'a> = &'a QualName;

    fn finish(self) -> Handle {
        self.document
    }

    fn parse_error(&self, _: Cow<'static, str>) {}

    fn get_document(&self) -> Handle {
        self.document.clone()
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> &'a QualName {
        match &target.data {
            Data::Element { name, .. } => name,
            _ => unreachable!("html5ever asks only elements for their names"),
        }
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        let template = flags.template.then(|| Node::new(Data::Document));
        Node::new(Data::Element { name, attrs: RefCell::new(attrs), template, mathml_integration_point: flags.mathml_annotation_xml_integration_point })
    }

    fn create_comment(&self, text: StrTendril) -> Handle {
        Node::new(Data::Comment(text))
    }

    fn create_pi(&self, _: StrTendril, _: StrTendril) -> Handle {
        Node::new(Data::Other)
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        match child {
            NodeOrText::AppendNode(n) => append_node(parent, n),
            NodeOrText::AppendText(t) => {
                if !merge_text(parent.children.borrow().last(), &t) {
                    append_node(parent, Node::new(Data::Text(RefCell::new(t))));
                }
            }
        }
    }

    fn append_based_on_parent_node(&self, element: &Handle, prev_element: &Handle, child: NodeOrText<Handle>) {
        if element.parent.borrow().upgrade().is_some() { self.append_before_sibling(element, child) } else { self.append(prev_element, child) }
    }

    fn append_doctype_to_document(&self, _: StrTendril, _: StrTendril, _: StrTendril) {
        append_node(&self.document, Node::new(Data::Other));
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        match &target.data {
            Data::Element { template: Some(t), .. } => t.clone(),
            _ => unreachable!("html5ever asks only templates for their contents"),
        }
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        Rc::ptr_eq(x, y)
    }

    fn set_quirks_mode(&self, _: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Handle, child: NodeOrText<Handle>) {
        let Some(parent) = sibling.parent.borrow().upgrade() else { return };
        let node = match child {
            NodeOrText::AppendText(t) => {
                let ch = parent.children.borrow();
                let i = ch.iter().position(|c| Rc::ptr_eq(c, sibling)).unwrap_or(ch.len());
                if i > 0 && merge_text(ch.get(i - 1), &t) {
                    return;
                }
                Node::new(Data::Text(RefCell::new(t)))
            }
            NodeOrText::AppendNode(n) => {
                detach(&n);
                n
            }
        };
        *node.parent.borrow_mut() = Rc::downgrade(&parent);
        let mut ch = parent.children.borrow_mut();
        let i = ch.iter().position(|c| Rc::ptr_eq(c, sibling)).unwrap_or(ch.len());
        ch.insert(i, node);
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        if let Data::Element { attrs: existing, .. } = &target.data {
            let mut existing = existing.borrow_mut();
            let names: HashSet<QualName> = existing.iter().map(|a| a.name.clone()).collect();
            existing.extend(attrs.into_iter().filter(|a| !names.contains(&a.name)));
        }
    }

    fn remove_from_parent(&self, target: &Handle) {
        detach(target);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        let children = std::mem::take(&mut *node.children.borrow_mut());
        for c in &children {
            *c.parent.borrow_mut() = Rc::downgrade(new_parent);
        }
        new_parent.children.borrow_mut().extend(children);
    }

    fn is_mathml_annotation_xml_integration_point(&self, target: &Handle) -> bool {
        matches!(&target.data, Data::Element { mathml_integration_point: true, .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(html: &str) -> Vec<String> {
        doc(html).elements.iter().map(|e| e.name.clone()).collect()
    }

    #[test]
    fn builds_the_tree_a_browser_builds() {
        // `<noscript>` is raw text with scripting on: the img is real.
        assert!(names(r#"<noscript><p title="</noscript><img src=x onerror=alert(1)>">"#).contains(&"img".to_string()));
        // In SVG and MathML, `<style>` is markup, and `<img>` breaks out.
        assert!(names("<svg><style><img src=x onerror=alert(1)></style></svg>").contains(&"img".to_string()));
        assert!(names("<math><style><img src=x onerror=alert(1)></style></math>").contains(&"img".to_string()));
        // A lone quote in an unquoted value doesn't end the tag.
        let d = doc(r#"<p title=a"b onclick=alert(1)>"#);
        let p = d.elements.iter().find(|e| e.name == "p").unwrap();
        assert_eq!((p.get("title"), p.get("onclick")), (Some("a\"b"), Some("alert(1)")));
        // Raw text and comments hold no elements.
        for inert in ["<!-- <img onerror=x> -->", "<textarea><img onerror=x></textarea>", "<title><img onerror=x></title>", "<style><img onerror=x></style>"] {
            assert!(!names(inert).contains(&"img".to_string()), "{inert}");
        }
        // `<!-->` is an empty comment.
        assert!(names("<!--><img src=x onerror=alert(1)>-->").contains(&"img".to_string()));
    }

    #[test]
    fn keeps_scripts_names_and_fragments() {
        let d = doc("<script>var a = '<b>';</script><svg><a xlink:href=\"javascript:x\"/></svg><p>Hi &amp; bye</p>");
        assert_eq!(d.elements.iter().find(|e| e.name == "script").and_then(|e| e.body.as_deref()), Some("var a = '<b>';"));
        assert!(d.elements.iter().any(|e| e.get("xlink:href") == Some("javascript:x")));
        assert!(d.text.contains("Hi & bye") && !d.text.contains("var a"));
        // Table parts outside a table survive.
        assert!(doc("<tr><td onclick=go()>x</td></tr>").elements.iter().any(|e| e.name == "td" && e.get("onclick").is_some()));
        // Template contents count: a script can clone them.
        assert!(names("<template><img src=x onerror=y></template>").contains(&"img".to_string()));
        // `<body onload>` in a fragment ends up on the body.
        assert!(doc("<p>x</p><body onload=go()>").elements.iter().any(|e| e.name == "body" && e.get("onload").is_some()));
    }

    #[test]
    fn deep_markup_stays_fast() {
        // 1 MB of nesting: the parser's scope checks would take minutes.
        let t = std::time::Instant::now();
        for open in ["<div>", "<b>", "<div></x>"] {
            let html = open.repeat(1_000_000 / open.len());
            assert!(doc(&html).elements.len() > 100_000, "{open}");
        }
        assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
        // The tag reader still sees what the markup holds.
        let html = format!("{}<img src=x onerror=alert(1)>", "<div>".repeat(2000));
        assert!(doc(&html).elements.iter().any(|e| e.get("onerror").is_some()));
        // Ordinary pages: long lists and tables with implied ends stay shallow.
        assert_eq!(depth(&"<li>x".repeat(5000)), 0);
        assert_eq!(depth(&"<tr><td>x".repeat(5000)), 0);
        assert_eq!(depth("<div><p>a<p>b<script>'<div><div>'</script></div>"), 1);
    }
}
