//! Just enough JavaScript to know where text sits: in code, in a string
//! (and which quote ends it), in a template, a comment or a regex literal.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    Code,
    Str(char),
    Template,
    Comment,
    Regex,
}

/// Words after which a `/` starts a regex literal rather than a division.
const BEFORE_REGEX: &[&str] = &["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"];

/// The place of each byte offset in `at` (ascending) in `src`.
pub(crate) fn places(src: &str, at: &[usize]) -> Vec<Place> {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(at.len());
    let mut next = at.iter().peekable();
    let mut st = Place::Code;
    // Brace depth, and the depths at which `${` opened a substitution.
    let (mut depth, mut subst): (usize, Vec<usize>) = (0, Vec::new());
    // In code: whether a `/` here starts a regex.
    let mut regex_ok = true;
    let mut in_class = false;
    let mut i = 0;
    loop {
        while next.peek().is_some_and(|&&a| a <= i) {
            next.next();
            out.push(st);
        }
        let Some(&c) = b.get(i) else { break };
        let n = b.get(i + 1).copied();
        match st {
            Place::Code => match c {
                b'\'' | b'"' => st = Place::Str(c as char),
                b'`' => st = Place::Template,
                b'/' if n == Some(b'/') => st = Place::Comment,
                b'/' if n == Some(b'*') => {
                    st = Place::Comment;
                    i += 1;
                    // Mark a block comment by skipping to its end now.
                    match src[i + 1..].find("*/") {
                        Some(e) => {
                            let end = i + 1 + e + 2;
                            while next.peek().is_some_and(|&&a| a < end) {
                                next.next();
                                out.push(Place::Comment);
                            }
                            i = end;
                            st = Place::Code;
                            continue;
                        }
                        None => i = b.len(),
                    }
                }
                b'/' if regex_ok => {
                    st = Place::Regex;
                    in_class = false;
                }
                b'{' => {
                    depth += 1;
                    regex_ok = true;
                }
                b'}' if subst.last() == Some(&depth) => {
                    subst.pop();
                    st = Place::Template;
                }
                b'}' => {
                    depth = depth.saturating_sub(1);
                    regex_ok = true;
                }
                c if c.is_ascii_whitespace() => {}
                c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' => {
                    let w = b[i..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_' || **c == b'$').count();
                    regex_ok = BEFORE_REGEX.contains(&&src[i..i + w]);
                    i += w;
                    continue;
                }
                b')' | b']' => regex_ok = false,
                _ => regex_ok = true,
            },
            Place::Str(q) => match c {
                b'\\' => i += 1,
                b'\n' => st = Place::Code,
                c if c as char == q => {
                    st = Place::Code;
                    regex_ok = false;
                }
                _ => {}
            },
            Place::Template => match c {
                b'\\' => i += 1,
                b'`' => {
                    st = Place::Code;
                    regex_ok = false;
                }
                b'$' if n == Some(b'{') => {
                    depth += 1;
                    subst.push(depth);
                    st = Place::Code;
                    regex_ok = true;
                    i += 1;
                }
                _ => {}
            },
            Place::Comment => {
                if c == b'\n' {
                    st = Place::Code;
                }
            }
            Place::Regex => match c {
                b'\\' => i += 1,
                b'[' => in_class = true,
                b']' => in_class = false,
                b'/' if !in_class => {
                    st = Place::Code;
                    regex_ok = false;
                }
                b'\n' => st = Place::Code,
                _ => {}
            },
        }
        i += 1;
    }
    out.extend(next.map(|_| st));
    out
}

/// How text placed in JavaScript source can run: a quote of its own ends
/// the string it was put in, or it was put in as code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Breakout {
    Quote,
    Code,
}

/// Whether `id` (the start of a canary whose rest is `tail`) breaks out
/// anywhere in the JavaScript source `src`.
pub(crate) fn breakout(src: &str, id: &str, tail: &str) -> Option<Breakout> {
    let at: Vec<usize> = src.match_indices(id).map(|(i, _)| i).collect();
    for (&i, place) in at.iter().zip(places(src, &at)) {
        match place {
            Place::Code => return Some(Breakout::Code),
            Place::Str(q) if ends_string(src, i + id.len(), q, tail) => return Some(Breakout::Quote),
            _ => {}
        }
    }
    None
}

/// Whether `tail`, written into a string closed by `quote` and found in
/// `src` from byte `from` on, ends that string: one of its quotes comes
/// through unescaped. The app may drop or escape characters of the tail
/// (JS escapes, HTML entities); a quote counts only after a letter of the
/// tail came through, so the app's own closing quote never does.
pub(crate) fn ends_string(src: &str, from: usize, quote: char, tail: &str) -> bool {
    let tail: Vec<char> = tail.chars().collect();
    let mut rest = &src[from..];
    let (mut k, mut ours) = (0, false);
    while k < tail.len() {
        let Some((got, escaped, len)) = next_char(rest) else { return false };
        let Some(j) = tail[k..].iter().position(|&w| w == got) else { return false };
        k += j + 1;
        ours |= got.is_alphanumeric();
        if got == quote && !escaped {
            return ours;
        }
        rest = &rest[len..];
    }
    false
}

/// `%27` → `'`, as a browser decodes a `javascript:` URL before running it.
pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The next character of a string literal's source, whether it was
/// escaped, and how many bytes it took.
fn next_char(s: &str) -> Option<(char, bool, usize)> {
    let mut it = s.chars();
    let c = it.next()?;
    if c == '&'
        && let Some(end) = s.get(..12).unwrap_or(s).find(';')
        && let d = crate::urls::decode_entities(&s[..=end])
        && d.chars().count() == 1
    {
        // An HTML entity: in a script it is text, never the quote.
        return Some((d.chars().next()?, true, end + 1));
    }
    if c != '\\' {
        return Some((c, false, c.len_utf8()));
    }
    let e = it.next()?;
    let hex = |h: &str| u32::from_str_radix(h, 16).ok().and_then(char::from_u32);
    let r = &s[2..];
    match e {
        'x' => Some((hex(r.get(..2)?)?, true, 4)),
        'u' if r.starts_with('{') => {
            let end = r.find('}')?;
            Some((hex(&r[1..end])?, true, 2 + end + 1))
        }
        'u' => Some((hex(r.get(..4)?)?, true, 6)),
        'n' => Some(('\n', true, 2)),
        't' => Some(('\t', true, 2)),
        e => Some((e, true, 1 + e.len_utf8())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(src: &str, needle: &str) -> Place {
        places(src, &[src.find(needle).unwrap()])[0]
    }

    #[test]
    fn finds_the_place() {
        assert_eq!(at("var q = 'X';", "X"), Place::Str('\''));
        assert_eq!(at("var q = \"a\\\"X\";", "X"), Place::Str('"'));
        assert_eq!(at("var q = X;", "X"), Place::Code);
        assert_eq!(at("var q = `a ${b + 'X'} c`;", "X"), Place::Str('\''));
        assert_eq!(at("var q = `a ${b} X`;", "X"), Place::Template);
        assert_eq!(at("// 'X\nvar a;", "X"), Place::Comment);
        assert_eq!(at("/* 'X */ var a;", "X"), Place::Comment);
        assert_eq!(at("/* a */ var a = 'X';", "X"), Place::Str('\''));
        assert_eq!(at("var r = /'/; var s = \"X\";", "X"), Place::Str('"'));
        assert_eq!(at("var d = a / 2 / 'X';", "X"), Place::Str('\''));
        assert_eq!(at("if (x) return /X'/.test(y);", "X"), Place::Regex);
        assert_eq!(at("var o = {a: {b: 1}}; f('X');", "X"), Place::Str('\''));
    }

    #[test]
    fn sees_a_quote_end_the_string() {
        let tail = "<i>'\"";
        // The quote that closes the string comes through raw.
        assert!(ends_string("var q = 'X<i>'\"';", 10, '\'', tail));
        assert!(ends_string("var q = \"X<i>'\"\";", 10, '"', tail));
        // Escaped by the app: JSON, JS escapes, a backslash.
        assert!(!ends_string("var q = \"X<i>'\\\"\";", 10, '"', tail));
        assert!(!ends_string("var q = 'X\\x3ci\\x3e\\x27\\x22';", 10, '\'', tail));
        assert!(!ends_string("var q = 'X\\u003ci>\\'\"';", 10, '\'', tail));
        // HTML entities in a script are text, not quotes.
        assert!(!ends_string("var q = 'X&lt;i&gt;&#39;&quot;';", 10, '\'', tail));
        // Escaping `<` alone, as HTML, leaves the quote.
        assert!(ends_string("var q = 'X&lt;i&gt;'\"';", 10, '\'', tail));
        // Dropping characters leaves it too, but the app's own quote is not ours.
        assert!(ends_string("var q = 'Xi'\"';", 10, '\'', tail));
        assert!(!ends_string("var q = 'X';", 10, '\'', tail));
        assert!(!ends_string("var q = 'X' + '<i>';", 10, '\'', tail));
    }

    #[test]
    fn breaks_out_of_code() {
        let tail = "<i>'\"";
        assert_eq!(breakout("f('X<i>'\"')", "X", tail), Some(Breakout::Quote));
        assert_eq!(breakout("f(\"X\\u003ci>'\\\"\")", "X", tail), None);
        assert_eq!(breakout("var n = X;", "X", tail), Some(Breakout::Code));
        assert_eq!(breakout("// X<i>'\"", "X", tail), None);
        assert_eq!(percent_decode("f('X%3Ci%3E%27%22')"), "f('X<i>'\"')");
    }
}
