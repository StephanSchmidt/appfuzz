//! CSS component values retain token boundaries and native end-of-input
//! recovery. A flat record stream avoids a deeply recursive JSON structure.
use cssparser::{ParseError, Parser, ToCss, Token};
use serde_json::{Value, json};

pub fn components(source: &str) -> Value {
    let mut parser = Parser::new(source);
    let mut records = vec![json!(["root", -1, "", "", false, false])];
    let limited = read(&mut parser, &mut records, 0, false).is_err();
    json!({"limited": limited, "tokens": records})
}

fn read<'i>(parser: &mut Parser<'i>, records: &mut Vec<Value>, parent: usize, mut numbers: bool) -> Result<(), ParseError<()>> {
    let mut previous = None;
    let mut comment = false;
    while let Ok(token) = parser.next_including_whitespace_and_comments().cloned() {
        let index = records.len();
        let mut text = canonical_escapes(&token.to_css_string());
        let joined = comment && previous.as_ref().is_some_and(|before| changes_tokens(before, &token));
        let bad = token.is_parse_error()
            || (joined && !numbers)
            || matches!(token, Token::Hash(_))
            || (!numbers && matches!(token, Token::Number { .. } | Token::Dimension { .. } | Token::Percentage { .. }));
        if joined && numbers {
            text.insert(0, ' ');
        }
        // In nth selectors, comments can separate An+B tokens and the `of`
        // keyword. Preserve that separation before the strict backend parses it.
        if numbers && matches!(&token, Token::Ident(name) if name.eq_ignore_ascii_case("of")) {
            text = " of ".into();
            numbers = false;
        }
        let (kind, close) = match token {
            Token::Function(_) => ("function", ")"),
            Token::ParenthesisBlock => ("block", ")"),
            Token::SquareBracketBlock => ("block", "]"),
            Token::CurlyBracketBlock => ("block", "}"),
            Token::Comma => ("comma", ""),
            Token::Comment(_) => ("comment", ""),
            _ => ("token", ""),
        };
        let detail = if let Token::Function(ref name) = token { json!(name.to_ascii_lowercase()) } else { json!(token.is_parse_error()) };
        records.push(json!([kind, parent, text, close, detail, bad]));
        if matches!(token, Token::Comment(_)) {
            comment = true;
        } else {
            previous = Some(token.clone());
            comment = false;
        }
        if !close.is_empty() {
            let numbers = matches!(&token, Token::Function(name) if matches!(name.to_ascii_lowercase().as_str(), "nth-child" | "nth-last-child" | "nth-of-type" | "nth-last-of-type"));
            parser.parse_nested_block(|nested| {
                if matches!(token, Token::SquareBracketBlock) {
                    let start = nested.state();
                    let valid = attribute_valid(nested);
                    nested.reset(&start);
                    if !valid {
                        records[index][5] = Value::Bool(true);
                    }
                }
                read(nested, records, index, numbers)
            })?;
        }
    }
    Ok(())
}

// Attribute names and unquoted values are CSS identifiers, not arbitrary text.
// Namespace separators are adjacent tokens; modifiers follow a matched value.
fn attribute_valid(input: &mut Parser<'_>) -> bool {
    match input.next().cloned() {
        Ok(Token::Ident(_)) => {
            let start = input.state();
            if matches!(input.next_including_whitespace(), Ok(Token::Delim('|'))) {
                if !matches!(input.next_including_whitespace(), Ok(Token::Ident(_))) {
                    return false;
                }
            } else {
                input.reset(&start);
            }
        }
        Ok(Token::Delim('*')) => {
            if !matches!(input.next_including_whitespace(), Ok(Token::Delim('|'))) || !matches!(input.next_including_whitespace(), Ok(Token::Ident(_))) {
                return false;
            }
        }
        Ok(Token::Delim('|')) => {
            if !matches!(input.next_including_whitespace(), Ok(Token::Ident(_))) {
                return false;
            }
        }
        _ => return false,
    }
    let Ok(matcher) = input.next().cloned() else {
        return true;
    };
    if !matches!(matcher, Token::Delim('=') | Token::IncludeMatch | Token::DashMatch | Token::PrefixMatch | Token::SuffixMatch | Token::SubstringMatch) {
        return false;
    }
    if !matches!(input.next(), Ok(Token::Ident(_) | Token::QuotedString(_))) {
        return false;
    }
    match input.next() {
        Err(_) => true,
        Ok(Token::Ident(value)) if value.eq_ignore_ascii_case("i") || value.eq_ignore_ascii_case("s") => input.is_exhausted(),
        _ => false,
    }
}

// Fixed-width hex escapes do not introduce whitespace which the strict
// backend could mistake for the end of an unquoted attribute value.
fn canonical_escapes(source: &str) -> String {
    let mut chars = source.chars().peekable();
    let mut out = String::with_capacity(source.len());
    while let Some(ch) = chars.next() {
        out.push(ch);
        if ch != '\\' {
            continue;
        }
        let mut hex = String::new();
        while hex.len() < 6 && chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            hex.push(chars.next().unwrap());
        }
        if hex.is_empty() {
            if let Some(ch) = chars.next() {
                out.push(ch);
            }
        } else {
            for _ in hex.len()..6 {
                out.push('0');
            }
            out.push_str(&hex);
            if chars.peek().is_some_and(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')) {
                let first = chars.next().unwrap();
                if first == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
        }
    }
    out
}

// Removing a CSS comment must not join separate tokens into a different one.
// Compare only risky pairs; signed nth coefficients remain separate tokens.
fn changes_tokens(before: &Token<'_>, after: &Token<'_>) -> bool {
    if !before.serialization_type().needs_separator_when_before(after.serialization_type()) {
        return false;
    }
    let source = format!("{}{}", canonical_escapes(&before.to_css_string()), canonical_escapes(&after.to_css_string()));
    let mut parser = Parser::new(&source);
    parser.next_including_whitespace_and_comments().ok() != Some(before)
        || parser.next_including_whitespace_and_comments().ok() != Some(after)
        || parser.next_including_whitespace_and_comments().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_preserve_token_boundaries_and_identifier_validity() {
        let invalid = components("b/**/b");
        assert_eq!(invalid["tokens"].as_array().unwrap().last().unwrap()[5], true);
        let valid = components(":nth-child(2n/**/+1)");
        assert!(valid["tokens"].as_array().unwrap().iter().all(|v| v[5] != true));
        assert!(components(":not(#123)")["tokens"].as_array().unwrap().iter().any(|v| v[2] == "#123" && v[5] == true));
        assert!(components("[x=\\31 23]")["tokens"].as_array().unwrap().iter().any(|v| v[2] == "\\00003123"));
    }

    #[test]
    fn eof_closes_blocks_strings_and_comments() {
        let value = components(":is([x=\"yes");
        assert_eq!(value["limited"], false);
        let tokens = value["tokens"].as_array().unwrap();
        assert!(tokens.iter().any(|v| v[0] == "function" && v[4] == "is"));
        assert!(tokens.iter().any(|v| v[2] == "[" && v[3] == "]"));
        assert!(tokens.iter().any(|v| v[2] == "\"yes\""));
        assert_eq!(components(".a/*unfinished")["tokens"][3][2], "/*unfinished*/");
    }

    #[test]
    fn escaped_function_names_decode_and_bad_closers_remain_bad() {
        let value = components(":\\69 s(.a,[)");
        assert_eq!(value["tokens"][2][4], "is");
        assert!(value["tokens"].as_array().unwrap().iter().any(|v| v[2] == ")" && v[4] == true));
    }

    #[test]
    fn excessive_nesting_is_bounded_without_native_stack_overflow() {
        let source = format!("{}a{}", ":is(".repeat(20_000), ")".repeat(20_000));
        assert_eq!(components(&source)["limited"], true);
    }
}
