//! Pagination: does the app read the pages the platform hands out?
//!
//! - in one run: rows between two pages the app read that it never read (it
//!   counts offsets by what it asked for, not what it got), or the first
//!   page again before the walk reached the last one: `broken_pagination`
//! - in a pair: the same world with shorter pages, where the platform says
//!   pages may be short, changes the answer: `broken_pagination`

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::dataset::{Page, Query, decode_cursor};
use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::record::{HostCall, RunRecord};

/// One page the app read.
#[derive(Debug, Clone, PartialEq)]
struct Window {
    call: u32,
    start: usize,
    items: usize,
    asked: usize,
    /// The platform said more rows follow (a `next`).
    more: bool,
    /// The platform said none follow: an empty page, `next` none, or a page
    /// shorter than asked where pages are never short.
    last: bool,
}

fn arg<'a>(args: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let (root, rest) = path.split_once('.').unwrap_or((path, ""));
    crate::harness::field(args.get(root)?, rest).and_then(crate::value::some)
}

fn failed(e: &HostCall) -> bool {
    e.trap.is_some() || e.result.as_ref().is_none_or(|v| v.get("err").is_some())
}

fn paged<'a>(m: &'a Manifest, func: &str) -> Option<(&'a Query, &'a Page)> {
    let q = m.function(func)?.query.as_ref()?;
    Some((q, q.page.as_ref()?))
}

/// Where a call's page starts, as the platform reads its arguments, and
/// what it answered. None for a cursor the platform never handed out.
fn window(q: &Query, page: &Page, e: &HostCall) -> Option<Window> {
    let offset = page.offset.as_deref().and_then(|p| arg(&e.args, p));
    let cursor = page.cursor.as_deref().and_then(|p| arg(&e.args, p)).and_then(Value::as_str).filter(|c| !c.is_empty());
    let start = match (offset, cursor) {
        (Some(o), _) => o.as_u64().map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX)),
        (None, Some(token)) => decode_cursor(&q.dataset, token)?,
        (None, None) => 0,
    };
    let asked = page
        .limit
        .as_deref()
        .and_then(|p| arg(&e.args, p))
        .and_then(Value::as_u64)
        .map_or(page.max, |n| usize::try_from(n).unwrap_or(usize::MAX).min(page.max));
    let items = e.result_items? as usize;
    let body = e.result.as_ref()?;
    let body = q.wrap.as_ref().and_then(|w| body.get(w)).unwrap_or(body);
    let next = page.next.as_ref().and_then(|f| body.get(f));
    Some(Window {
        call: e.call,
        start,
        items,
        asked,
        more: next.is_some_and(|v| !v.is_null()),
        last: items == 0 || next.is_some_and(Value::is_null) || (!page.short && items < asked),
    })
}

/// The arguments without the page's position and size: calls with the same
/// group walk the same list.
fn group(page: &Page, args: &Map<String, Value>) -> String {
    let mut v = Value::Object(args.clone());
    for p in [&page.limit, &page.offset, &page.cursor].into_iter().flatten() {
        if let Some(x) = crate::harness::field_mut(&mut v, p) {
            *x = Value::Null;
        }
    }
    v.to_string()
}

/// The pages a run read, per function and list, up to the first failed call.
fn walks<'a>(r: &'a RunRecord, m: &'a Manifest) -> BTreeMap<(&'a str, String), Vec<Window>> {
    let mut walks: BTreeMap<(&str, String), (Vec<Window>, bool)> = BTreeMap::new();
    for e in &r.events {
        let Some((q, page)) = paged(m, &e.func) else { continue };
        let (windows, stopped) = walks.entry((e.func.as_str(), group(page, &e.args))).or_default();
        if *stopped {
            continue;
        }
        // After a failure the app may start over or give up: both are fine.
        if failed(e) {
            *stopped = true;
            continue;
        }
        windows.extend(window(q, page, e));
    }
    walks.into_iter().map(|(k, (w, _))| (k, w)).collect()
}

/// Rows between pages the app read that it never read: the first such gap.
fn gap(windows: &[Window]) -> Option<(&Window, &Window, usize)> {
    let mut sorted: Vec<&Window> = windows.iter().collect();
    sorted.sort_by_key(|w| (w.start, std::cmp::Reverse(w.items)));
    let (first, rest) = sorted.split_first()?;
    let mut reach = (first.start + first.items, *first);
    for w in rest {
        // Rows exist up to `w.start` when `w` has rows, or when the page
        // that ends at `reach` said more follow.
        if w.start > reach.0 && (w.items > 0 || reach.1.more) {
            return Some((reach.1, w, reach.0));
        }
        if w.start + w.items > reach.0 {
            reach = (w.start + w.items, w);
        }
    }
    None
}

/// The first page again while the walk was still going.
fn restart(windows: &[Window]) -> Option<(&Window, &Window)> {
    let mut far = 0;
    for pair in windows.windows(2) {
        far = far.max(pair[0].start);
        if pair[1].start == 0 && far > 0 && !pair[0].last {
            return Some((&pair[0], &pair[1]));
        }
    }
    None
}

pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    for ((func, _), windows) in walks(r, m) {
        if let Some((before, after, from)) = gap(&windows) {
            let got = if before.items < before.asked { format!(" (it asked for {} and got {})", before.asked, before.items) } else { String::new() };
            out.push(Finding::new(
                "broken_pagination",
                &format!("{ex}\0{func}\0gap"),
                Severity::Fail,
                format!(
                    "{ex} never reads rows {from} to {} of {func}: the page from row {} had {} rows{got}, and the next page it asks for starts at row {}",
                    after.start - 1,
                    before.start,
                    before.items,
                    after.start
                ),
                json!({"func": func, "gap": [from, after.start], "calls": [before.call, after.call], "asked": before.asked, "got": before.items}),
                run,
            ));
        }
        if let Some((before, again)) = restart(&windows) {
            out.push(Finding::new(
                "broken_pagination",
                &format!("{ex}\0{func}\0restart"),
                Severity::Fail,
                format!(
                    "{ex} reads the first page of {func} again (call {}) before it reaches the last page; it had read on to row {}",
                    again.call, before.start
                ),
                json!({"func": func, "calls": [before.call, again.call]}),
                run,
            ));
        }
    }
    out
}

/// Shorter page sizes worth trying, where the platform may return short
/// pages and the run read more than one page of a function: 1, and one less
/// than asked, each below the longest page the run got.
pub fn shorter(m: &Manifest, r: &RunRecord) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for e in &r.events {
        if seen.contains(&e.func.as_str()) {
            continue;
        }
        seen.push(&e.func);
        let Some((q, page)) = paged(m, &e.func).filter(|(_, p)| p.short) else { continue };
        let calls: Vec<&HostCall> = r.events.iter().filter(|x| x.func == e.func).collect();
        if calls.len() < 2 || calls.iter().any(|x| failed(x)) {
            continue;
        }
        let longest = calls.iter().filter_map(|x| x.result_items).max().unwrap_or(0) as usize;
        let asked = window(q, page, calls[0]).map_or(page.max, |w| w.asked);
        let mut sizes = vec![1, asked.saturating_sub(1)];
        sizes.retain(|&s| s >= 1 && s < longest);
        sizes.dedup();
        out.extend(sizes.into_iter().map(|s| (e.func.clone(), s)));
    }
    out
}

/// A run whose answer changed when `func` returned pages of `size`.
pub fn shorter_finding(m: &Manifest, base: &RunRecord, vr: &RunRecord, func: &str, size: usize, mut detail: Value) -> Finding {
    let ex = &base.spec.export;
    let rows = |r: &RunRecord| r.events.iter().filter(|e| e.func == func).filter_map(|e| e.result_items).map(u64::from).sum::<u64>();
    let (all, read) = (rows(base), rows(vr));
    let asked = paged(m, func).and_then(|(q, page)| window(q, page, base.events.iter().find(|e| e.func == func)?)).map(|w| w.asked);
    let asked_text = asked.map(|a| format!(" (it asked for {a})")).unwrap_or_default();
    let mut title = format!("{ex} answers differently when {func} returns pages of {size}{asked_text}");
    if read < all {
        title.push_str(&format!(": it reads {read} of the {all} rows and stops at a short page"));
    }
    if let Value::Object(d) = &mut detail {
        d.extend([
            ("page_size".to_string(), json!(size)),
            ("asked".to_string(), json!(asked)),
            ("rows".to_string(), json!(all)),
            ("rows_read".to_string(), json!(read)),
        ]);
    }
    Finding::new("broken_pagination", &format!("{ex}\0{func}\0pages"), Severity::Fail, title, detail, Some(&vr.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(call: u32, start: usize, items: usize, asked: usize, more: bool, last: bool) -> Window {
        Window { call, start, items, asked, more, last }
    }

    #[test]
    fn a_page_counted_by_what_was_asked_skips_rows() {
        // Pages of 3 where 10 were asked: the app jumps to 10.
        let walk = [w(1, 0, 3, 10, false, false), w(2, 10, 1, 10, false, false), w(3, 20, 0, 10, false, true)];
        let (before, after, from) = gap(&walk).unwrap();
        assert_eq!((before.call, after.call, from), (1, 2, 3));
        // Following what the platform returned leaves no gap; overlaps
        // (a lookahead row) are fine.
        let walk = [w(1, 0, 3, 10, false, false), w(2, 3, 3, 10, false, false), w(3, 5, 2, 10, false, false), w(4, 7, 0, 10, false, true)];
        assert!(gap(&walk).is_none());
        // An empty page past a jump says nothing, unless the platform said
        // more rows follow.
        assert!(gap(&[w(1, 0, 3, 10, false, false), w(2, 10, 0, 10, false, true)]).is_none());
        assert!(gap(&[w(1, 0, 3, 10, true, false), w(2, 10, 0, 10, false, true)]).is_some());
        // One page from the middle (a pager on page 3) is no gap.
        assert!(gap(&[w(1, 20, 10, 10, false, false)]).is_none());
    }

    #[test]
    fn the_first_page_again_counts_only_before_the_last_page() {
        assert!(restart(&[w(1, 0, 10, 10, true, false), w(2, 10, 10, 10, true, false), w(3, 0, 10, 10, true, false)]).is_some());
        // Listing everything twice reaches the end first.
        assert!(restart(&[w(1, 0, 10, 10, true, false), w(2, 10, 0, 10, false, true), w(3, 0, 10, 10, true, false)]).is_none());
        // A peek at the first row, then the walk.
        assert!(restart(&[w(1, 0, 1, 1, true, false), w(2, 0, 10, 10, true, false)]).is_none());
    }
}
