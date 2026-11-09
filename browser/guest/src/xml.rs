//! XML network decoding and an inert DOM recipe. Namespace validation and
//! normalized attributes come from roxmltree; XML events preserve node kinds
//! that a read-only XML tree intentionally coalesces. Neither parser resolves
//! external resources.
use serde_json::{Value, json};
use std::collections::HashMap;

fn element_data(node: roxmltree::Node<'_, '_>, source: &str, parent: usize) -> Option<Value> {
    let tag = &source[node.range()];
    let name = tag[1..].split([' ', '\t', '\r', '\n', '/', '>']).next()?;
    let attributes: HashMap<_, _> = node.attributes().map(|a| (&source[a.range_qname()], a)).collect();
    let namespaces: HashMap<_, _> = node.namespaces().map(|ns| (ns.name(), ns.uri())).collect();
    let mut attrs = Vec::new();
    let mut rest = &tag[1 + name.len()..];
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        if rest.starts_with(['/', '>']) {
            break;
        }
        let end = rest.find([' ', '\t', '\r', '\n', '='])?;
        let key = &rest[..end];
        rest = rest[end..].trim_start_matches([' ', '\t', '\r', '\n']).strip_prefix('=')?.trim_start_matches([' ', '\t', '\r', '\n']);
        let quote = rest.chars().next()?;
        rest = &rest[quote.len_utf8()..];
        let end = rest.find(quote)?;
        if key == "xmlns" || key.starts_with("xmlns:") {
            let prefix = key.strip_prefix("xmlns:");
            attrs.push(json!([key, roxmltree::NS_XMLNS_URI, namespaces.get(&prefix).copied().unwrap_or("")]));
        } else {
            let a = attributes.get(key)?;
            attrs.push(json!([key, a.namespace(), a.value()]));
        }
        rest = &rest[end + quote.len_utf8()..];
    }
    Some(json!(["element", parent, name, node.tag_name().namespace(), attrs]))
}

pub(crate) fn xml_tree(value: &str) -> Option<Value> {
    use ::xml::{
        Encoding,
        reader::{ParserConfig, XmlEvent},
    };
    let doc = roxmltree::Document::parse_with_options(value, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() }).ok()?;
    let mut elements = doc.descendants().filter(roxmltree::Node::is_element);
    // The network bytes have already been decoded using the browser's Encoding
    // Standard rules. A declaration must not decode that UTF-8 string again.
    let mut reader = ParserConfig::new()
        .ignore_comments(false)
        .cdata_to_characters(false)
        .whitespace_to_characters(true)
        .override_encoding(Some(Encoding::Utf8))
        .ignore_invalid_encoding_declarations(true)
        .create_reader(value.as_bytes());
    let mut result = vec![json!(["root", null])];
    let mut parents = vec![0];
    loop {
        let parent = *parents.last()?;
        match reader.next().ok()? {
            XmlEvent::StartDocument { .. } => {}
            XmlEvent::StartElement { name, .. } => {
                let node = elements.next()?;
                if node.tag_name().name() != name.local_name || node.tag_name().namespace() != name.namespace.as_deref().filter(|s| !s.is_empty()) {
                    return None;
                }
                let at = result.len();
                result.push(element_data(node, value, parent)?);
                parents.push(at);
            }
            XmlEvent::EndElement { .. } => {
                if parents.len() == 1 {
                    return None;
                }
                parents.pop();
            }
            XmlEvent::Characters(text) | XmlEvent::Whitespace(text) => {
                if parent != 0 && !text.is_empty() {
                    result.push(json!(["text", parent, text]));
                }
            }
            XmlEvent::CData(text) => result.push(json!(["cdata", parent, text])),
            XmlEvent::Comment(text) => result.push(json!(["comment", parent, text])),
            XmlEvent::ProcessingInstruction { name, data } => result.push(json!(["pi", parent, name, data.unwrap_or_default()])),
            XmlEvent::Doctype { .. } => {
                let ids = reader.doctype_ids()?;
                result.push(json!(["doctype", parent, ids.name(), ids.public_id().unwrap_or(""), ids.system_id().unwrap_or("")]));
            }
            XmlEvent::EndDocument => {
                return (parents.len() == 1 && elements.next().is_none()).then_some(Value::Array(result));
            }
        }
    }
}

fn declared_encoding(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes.get(..bytes.windows(2).position(|p| p == b"?>")? + 2)?).ok()?;
    let mut text = text.strip_prefix("<?xml")?;
    if !text.starts_with([' ', '\t', '\r', '\n']) {
        return None;
    }
    loop {
        text = text.trim_start_matches([' ', '\t', '\r', '\n']);
        let end = text.find([' ', '\t', '\r', '\n', '='])?;
        let key = &text[..end];
        text = text[end..].trim_start_matches([' ', '\t', '\r', '\n']).strip_prefix('=')?.trim_start_matches([' ', '\t', '\r', '\n']);
        let quote = text.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        text = &text[1..];
        let end = text.find(quote)?;
        if key == "encoding" {
            return Some(&text[..end]);
        }
        text = &text[end + 1..];
    }
}

pub(crate) fn decode(bytes: &[u8], label: Option<&str>, xml: bool, strict: bool) -> Value {
    use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE};
    let supplied = label.and_then(|s| Encoding::for_label(s.as_bytes()));
    let declared = if xml && supplied.is_none() { declared_encoding(bytes) } else { None };
    let declaration = declared.and_then(|s| Encoding::for_label(s.as_bytes()));
    let signature = if xml && supplied.is_none() {
        if bytes.starts_with(&[0, 60, 0, 63]) {
            Some(UTF_16BE)
        } else if bytes.starts_with(&[60, 0, 63, 0]) {
            Some(UTF_16LE)
        } else {
            None
        }
    } else {
        None
    };
    let (encoding, _) = Encoding::for_bom(bytes).unwrap_or((supplied.or(signature).or(declaration).unwrap_or(UTF_8), 0));
    let (text, _, errors) = encoding.decode(bytes);
    json!({"text":text,"encoding":encoding.name(),"valid":!strict || !errors})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cdata_boundaries_empty_sections_and_newlines() {
        let v = xml_tree("<root>a<![CDATA[b\r\nc]]>d&amp;e<![CDATA[]]></root>").unwrap();
        let children: Vec<_> = v.as_array().unwrap().iter().skip(2).map(|n| json!([n[0], n[2]])).collect();
        assert_eq!(children, json!([["text", "a"], ["cdata", "b\nc"], ["text", "d&e"], ["cdata", ""]]).as_array().unwrap().to_vec());
    }
    #[test]
    fn doctype_public_and_system_identifiers_are_nodes() {
        let v = xml_tree("<!DOCTYPE root PUBLIC '-//synthetic//EN' 'synthetic.dtd'><root/>").unwrap();
        assert_eq!(v[1], json!(["doctype", 0, "root", "-//synthetic//EN", "synthetic.dtd"]));
        assert_eq!(v[2][1], 0);
    }
    #[test]
    fn internal_entity_markup_has_real_parent_links() {
        let v = xml_tree("<!DOCTYPE r [<!ENTITY a 'synthetic'><!ENTITY b '<item>&a;</item>'>]><r>&b;</r>").unwrap();
        assert_eq!(v[3][0], "element");
        assert_eq!(v[3][1], 2);
        assert_eq!(v[3][2], "item");
        assert_eq!(v[4], json!(["text", 3, "synthetic"]));
    }
    #[test]
    fn attribute_order_includes_namespace_declarations() {
        let v = xml_tree("<r first='1' xmlns:p='urn:p' p:id='A' last='2'/>").unwrap();
        let names: Vec<_> = v[1][4].as_array().unwrap().iter().map(|a| a[0].as_str().unwrap()).collect();
        assert_eq!(names, ["first", "xmlns:p", "p:id", "last"]);
    }
    #[test]
    fn xml_declaration_and_explicit_text_modes() {
        let bytes = b"<?xml version='1.0' encoding='windows-1252'?><r>caf\xe9</r>";
        assert!(decode(bytes, None, true, true)["text"].as_str().unwrap().contains("café"));
        assert!(decode(bytes, None, false, false)["text"].as_str().unwrap().contains("caf�"));
        assert_eq!(decode(bytes, Some("utf-8"), true, true)["valid"], false);
    }
    #[test]
    fn bom_overrides_supplied_charset_and_signature_sniffs_utf16() {
        let v = decode(b"\xef\xbb\xbf<r>caf\xc3\xa9</r>", Some("windows-1252"), true, true);
        assert_eq!(v["text"], "<r>café</r>");
        assert_eq!(v["encoding"], "UTF-8");
        let bytes: Vec<_> = "<?xml version='1.0'?><r>synthetic</r>".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode(&bytes, None, true, true)["encoding"], "UTF-16LE");
    }
    #[test]
    fn malformed_bytes_fail_xml_but_text_remains_lossy() {
        assert_eq!(decode(b"<r>\xff</r>", None, true, true)["valid"], false);
        assert_eq!(decode(b"<r>\xff</r>", None, true, false)["text"], "<r>�</r>");
        assert_eq!(decode(b"<?xml version='1.0' encoding='unknown-synthetic'?><r/>", None, true, true)["valid"], true);
    }
}
