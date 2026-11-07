//! Where each finding kind sits in the standards security teams use: its
//! CWE, the OWASP Top 10 (2025) category whose mapped CWEs include it, and
//! the OWASP API Security Top 10 (2023) category it belongs to.
//!
//! The Top 10 category follows from the CWE: OWASP publishes the CWEs each
//! category covers (owasp.org/Top10/2025, read 2026-11-07), listed in
//! `TOP10` below. A CWE in none of them (resource exhaustion, timing) has no
//! Top 10 category; the API list covers resource consumption.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::manifest::Manifest;

/// A category of a Top 10 list.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Category {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    /// CWEs OWASP maps to it (Top 10 only).
    #[serde(skip)]
    pub cwes: &'static [u32],
    /// What the platform, not the app's review, has to cover.
    pub platform: &'static str,
}

pub const TOP10: &[Category] = &[
    Category {
        id: "A01",
        name: "Broken Access Control",
        url: "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        cwes: &[
            22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601,
            615, 639, 668, 732, 749, 862, 863, 918, 922, 1275,
        ],
        platform: "who may call which route (login, roles); appfuzz checks records of other users, not roles",
    },
    Category {
        id: "A02",
        name: "Security Misconfiguration",
        url: "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
        cwes: &[5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174],
        platform: "TLS, server headers and the settings of the hosts the app runs on",
    },
    Category {
        id: "A03",
        name: "Software Supply Chain Failures",
        url: "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
        cwes: &[447, 1035, 1104, 1329, 1357, 1395],
        platform: "known-vulnerable dependencies, builds and signing; appfuzz reviews the compiled app with everything inside it",
    },
    Category {
        id: "A04",
        name: "Cryptographic Failures",
        url: "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
        cwes: &[
            261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780,
            916, 1240, 1241,
        ],
        platform: "TLS, keys and how secrets are stored",
    },
    Category {
        id: "A05",
        name: "Injection",
        url: "https://owasp.org/Top10/2025/A05_2025-Injection/",
        cwes: &[
            20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564,
            610, 643, 644, 917,
        ],
        platform: "nothing beyond labelling the platform's sinks",
    },
    Category {
        id: "A06",
        name: "Insecure Design",
        url: "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
        cwes: &[
            73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653,
            656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125,
        ],
        platform: "the design itself: the team's acceptance checks and the platform's business rules say what the app must do",
    },
    Category {
        id: "A07",
        name: "Authentication Failures",
        url: "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
        cwes: &[
            258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640,
            798, 940, 941, 1390, 1391, 1392, 1393,
        ],
        platform: "login, passwords, sessions and multi-factor authentication",
    },
    Category {
        id: "A08",
        name: "Software or Data Integrity Failures",
        url: "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
        cwes: &[345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926],
        platform: "that the reviewed build is the one deployed",
    },
    Category {
        id: "A09",
        name: "Security Logging & Alerting Failures",
        url: "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
        cwes: &[117, 221, 223, 532, 778],
        platform: "collecting logs, keeping them and alerting on them",
    },
    Category {
        id: "A10",
        name: "Mishandling of Exceptional Conditions",
        url: "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
        cwes: &[209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756],
        platform: "restarting failed instances",
    },
];

pub const API: &[Category] = &[
    Category {
        id: "API1",
        name: "Broken Object Level Authorization",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API2",
        name: "Broken Authentication",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API3",
        name: "Broken Object Property Level Authorization",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API4",
        name: "Unrestricted Resource Consumption",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API5",
        name: "Broken Function Level Authorization",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API6",
        name: "Unrestricted Access to Sensitive Business Flows",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API7",
        name: "Server Side Request Forgery",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API8",
        name: "Security Misconfiguration",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API9",
        name: "Improper Inventory Management",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
        cwes: &[],
        platform: "",
    },
    Category {
        id: "API10",
        name: "Unsafe Consumption of APIs",
        url: "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
        cwes: &[],
        platform: "",
    },
];

/// What a check needs from the manifest before it can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Need {
    /// A parameter labelled `sql`, `shell`, `path`, `url`, `html` or `regex`.
    Sinks,
    /// `identity` labels: who the caller is.
    Identity,
    /// A dataset with an `owner`.
    Owners,
    /// `pii` or `secret` labels.
    Sensitive,
    /// Output labels on the export's result.
    Output,
    /// A body labelled `html:scripts`.
    Scripts,
    /// An HTTP request with headers.
    Http,
    /// `effect` labels on functions.
    Effects,
}

impl Need {
    pub fn why(self) -> &'static str {
        match self {
            Need::Sinks => "no parameter is labelled sql, shell, path, url, html or regex",
            Need::Identity => "no identity labels: appfuzz doesn't know who the caller is",
            Need::Owners => "no dataset declares an owner",
            Need::Sensitive => "no pii or secret labels",
            Need::Output => "no output labels on the response",
            Need::Scripts => "the response is not labelled html:scripts",
            Need::Http => "the export takes no HTTP request with headers",
            Need::Effects => "no function has an effect label",
        }
    }
}

/// Where a finding kind sits.
#[derive(Debug, Clone, Copy)]
pub struct Standard {
    pub cwe: Option<u32>,
    /// OWASP API Security Top 10 (2023) category, e.g. "API4".
    pub api: Option<&'static str>,
    pub need: Option<Need>,
}

const fn s(cwe: u32, api: Option<&'static str>, need: Option<Need>) -> Option<Standard> {
    Some(Standard { cwe: Some(cwe), api, need })
}

/// The standards of finding `kind`. None for kinds that are about quality,
/// not security (n+1 queries, order dependence, failed acceptance checks).
pub fn of(kind: &str) -> Option<Standard> {
    use Need::*;
    match kind {
        // Injection.
        "sql_injection" => s(89, None, Some(Sinks)),
        "command_injection" => s(78, None, Some(Sinks)),
        "html_injection" => s(79, None, Some(Sinks)),
        "regex_injection" => s(74, None, Some(Sinks)),
        "escaped_by_hand" => s(116, None, Some(Sinks)),
        "path_traversal" => s(22, None, Some(Sinks)),
        "ssrf" | "url_path_injection" => s(918, Some("API7"), Some(Sinks)),
        "reflection" | "script_in_output" => s(79, None, None),
        "stored_reflection" => s(79, Some("API10"), None),
        "input_passthrough" => s(20, None, None),
        "host_header_injection" => s(644, None, Some(Http)),
        "code_injection" => s(95, None, Some(Scripts)),
        "log_injection" => s(117, None, None),
        // Access to records and routes.
        "foreign_user_access" | "missing_owner_check" => s(639, Some("API1"), Some(Identity)),
        "tenant_leak" => s(668, Some("API1"), Some(Owners)),
        "mass_disclosure" => s(200, Some("API4"), None),
        "pii_leak" => s(359, Some("API3"), Some(Sensitive)),
        "secret_leak" => s(200, None, Some(Sensitive)),
        "open_redirect" | "non_local_url" => s(601, None, Some(Output)),
        "auto_navigation" => s(601, None, Some(Scripts)),
        "unsafe_action" => s(352, None, Some(Output)),
        "write_on_safe_method" => s(352, None, Some(Effects)),
        "ungranted_import" | "ungranted_call" => s(284, Some("API9"), None),
        // Configuration and transport.
        "permissive_cors" => s(942, Some("API8"), Some(Http)),
        "insecure_cookie" => s(1004, Some("API8"), None),
        "weak_csp" => s(693, Some("API8"), Some(Scripts)),
        "cleartext_transport" => s(319, Some("API8"), Some(Sensitive)),
        // Authentication.
        "auth_bypass" => s(287, Some("API2"), Some(Http)),
        "timing_unsafe_compare" => s(208, Some("API2"), Some(Http)),
        "predictable_token" => s(330, Some("API2"), Some(Http)),
        // Code from elsewhere, hostile code.
        "remote_code" => s(829, None, Some(Scripts)),
        "unpinned_script" => s(353, None, Some(Scripts)),
        "agent_directed_text" | "hidden_text" | "encoded_flow" | "constant_payload" | "unexpected_destination" | "probing" | "dormant_code" => {
            s(506, None, None)
        }
        // Errors.
        "crash" | "crash_at_time" => s(248, None, None),
        "crash_on_host_value" => s(248, Some("API10"), None),
        "leaky_error" => s(209, None, None),
        "error_ignored" => s(252, None, None),
        "continues_after_error" => s(755, None, None),
        "partial_write" => s(460, None, Some(Effects)),
        "invalid_host_argument" => s(628, None, None),
        // Resources.
        "hang" | "hang_at_time" => s(835, Some("API4"), None),
        "hang_on_host_value" => s(835, Some("API10"), None),
        "stack_overflow" => s(674, Some("API4"), None),
        "cpu_blowup" => s(407, Some("API4"), None),
        "memory_blowup" | "unbounded_read" | "input_amplification" => s(770, Some("API4"), None),
        "over_budget" | "fails_at_size" | "output_amplification" | "payload_amplification" | "big_output" | "big_payload" | "retry_storm" => {
            s(400, Some("API4"), None)
        }
        "n_plus_1" | "nested_fan_out" => s(1073, Some("API4"), None),
        "repeated_write" => s(837, Some("API6"), Some(Effects)),
        _ => None,
    }
}

/// The Top 10 (2025) category of a CWE.
pub fn top10(cwe: u32) -> Option<&'static Category> {
    TOP10.iter().find(|c| c.cwes.contains(&cwe))
}

pub fn api(id: &str) -> Option<&'static Category> {
    API.iter().find(|c| c.id == id)
}

/// The standards a finding JSON carries: `{"cwe": "CWE-89", "owasp":
/// "A05:2025", "owasp_api": "API8:2023"}`, each only when known.
pub fn json(kind: &str) -> Option<serde_json::Value> {
    let st = of(kind)?;
    let mut o = serde_json::Map::new();
    if let Some(c) = st.cwe {
        o.insert("cwe".into(), format!("CWE-{c}").into());
        if let Some(t) = top10(c) {
            o.insert("owasp".into(), format!("{}:2025", t.id).into());
        }
    }
    if let Some(a) = st.api {
        o.insert("owasp_api".into(), format!("{a}:2023").into());
    }
    Some(o.into())
}

/// Every kind appfuzz reports that has a Top 10 category.
pub const KINDS: &[&str] = &[
    "sql_injection",
    "command_injection",
    "html_injection",
    "regex_injection",
    "escaped_by_hand",
    "path_traversal",
    "ssrf",
    "url_path_injection",
    "reflection",
    "script_in_output",
    "stored_reflection",
    "input_passthrough",
    "host_header_injection",
    "code_injection",
    "log_injection",
    "foreign_user_access",
    "missing_owner_check",
    "tenant_leak",
    "mass_disclosure",
    "pii_leak",
    "secret_leak",
    "open_redirect",
    "non_local_url",
    "auto_navigation",
    "unsafe_action",
    "write_on_safe_method",
    "ungranted_import",
    "ungranted_call",
    "permissive_cors",
    "insecure_cookie",
    "weak_csp",
    "cleartext_transport",
    "auth_bypass",
    "timing_unsafe_compare",
    "predictable_token",
    "remote_code",
    "unpinned_script",
    "agent_directed_text",
    "hidden_text",
    "encoded_flow",
    "constant_payload",
    "unexpected_destination",
    "probing",
    "dormant_code",
    "crash",
    "crash_at_time",
    "crash_on_host_value",
    "leaky_error",
    "error_ignored",
    "continues_after_error",
    "partial_write",
    "invalid_host_argument",
    "hang",
    "hang_at_time",
    "hang_on_host_value",
    "stack_overflow",
    "cpu_blowup",
    "memory_blowup",
    "unbounded_read",
    "input_amplification",
    "over_budget",
    "fails_at_size",
    "output_amplification",
    "payload_amplification",
    "big_output",
    "big_payload",
    "retry_storm",
    "n_plus_1",
    "nested_fan_out",
    "repeated_write",
];

/// What the manifest lets appfuzz check.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    pub sinks: bool,
    pub identity: bool,
    pub owners: bool,
    pub sensitive: bool,
    pub output: bool,
    pub scripts: bool,
    pub http: bool,
    pub effects: bool,
}

impl Context {
    pub fn new(m: &Manifest, export: &str, request: Option<&serde_json::Value>) -> Context {
        use crate::labels::Label;
        let labels = m.functions.values().flat_map(|f| f.params.values().copied().chain(f.result.iter().flat_map(|r| r.paths()).map(|(_, l)| l)));
        Context {
            sinks: m.has_sinks(),
            identity: crate::identity::declared(m),
            owners: m.datasets.values().any(|d| d.owner.is_some()),
            sensitive: labels.into_iter().any(|l| matches!(l, Label::Pii | Label::Secret)),
            output: m.has_output_labels(),
            scripts: crate::browser::runs_scripts(m, export),
            http: request.is_some_and(|r| r.get("headers").is_some_and(serde_json::Value::is_array)),
            effects: m.functions.values().any(|f| f.effect.is_some()),
        }
    }

    pub fn has(&self, need: Need) -> bool {
        match need {
            Need::Sinks => self.sinks,
            Need::Identity => self.identity,
            Need::Owners => self.owners,
            Need::Sensitive => self.sensitive,
            Need::Output => self.output,
            Need::Scripts => self.scripts,
            Need::Http => self.http,
            Need::Effects => self.effects,
        }
    }
}

/// One Top 10 category in a review.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    /// Findings of this review in the category, fail and warn.
    pub found: usize,
    /// Kinds appfuzz checked.
    pub checked: Vec<&'static str>,
    /// Kinds it couldn't check, by what was missing.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub not_checked: BTreeMap<&'static str, Vec<&'static str>>,
    pub platform: &'static str,
}

/// The review's Top 10 table: per category, what was found, checked and not.
pub fn table(cx: &Context, found_kinds: &[&str]) -> Vec<Row> {
    TOP10
        .iter()
        .map(|c| {
            let mut row = Row { id: c.id, name: c.name, url: c.url, found: 0, checked: vec![], not_checked: BTreeMap::new(), platform: c.platform };
            row.found = found_kinds.iter().filter(|k| of(k).and_then(|s| s.cwe).and_then(top10).is_some_and(|t| t.id == c.id)).count();
            for k in KINDS {
                let Some(st) = of(k) else { continue };
                if st.cwe.and_then(top10).is_none_or(|t| t.id != c.id) {
                    continue;
                }
                match st.need.filter(|n| !cx.has(*n)) {
                    Some(n) => row.not_checked.entry(n.why()).or_default().push(k),
                    None => row.checked.push(k),
                }
            }
            row
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kinds the guide's tables list (AGENTS.md §6).
    fn documented() -> Vec<String> {
        let guide = include_str!("../../../AGENTS.md");
        let mut out = Vec::new();
        let mut in_table = false;
        for line in guide.lines() {
            if line.starts_with("| Kind |") {
                in_table = true;
                continue;
            }
            if !line.starts_with('|') {
                in_table = false;
                continue;
            }
            if !in_table || line.starts_with("|--") {
                continue;
            }
            let first = line.split('|').nth(1).unwrap_or_default();
            out.extend(first.split(',').map(|k| k.trim().trim_matches('`').to_string()).filter(|k| !k.is_empty()));
        }
        out
    }

    #[test]
    fn every_documented_kind_is_placed_or_known_to_be_quality() {
        const QUALITY: &[&str] = &[
            "redundant_calls",
            "chatty",
            "serial_chain",
            "host_call_in_loop",
            "busy_wait",
            "sleeps",
            "slow_host_sensitivity",
            "duplicate_sensitivity",
            "order_dependence",
            "nondeterminism",
            "broken_pagination",
            "invalid_response",
            "broken_markup",
            "inconsistent_response",
            "unused_grant",
            "check_failed",
            "acceptance_failed",
            "sequence_check_failed",
            "weak_assert",
            "script_error",
            "outside_envelope",
        ];
        let kinds = documented();
        assert!(kinds.len() > 80, "{kinds:?}");
        for k in &kinds {
            assert!(of(k).is_some() != QUALITY.contains(&k.as_str()), "{k}: place it in standards::of or list it as quality");
        }
        for k in KINDS {
            assert!(of(k).is_some(), "{k}");
        }
        for k in kinds.iter().filter(|k| of(k).is_some()) {
            assert!(KINDS.contains(&k.as_str()), "{k} is missing from KINDS");
        }
    }

    #[test]
    fn categories_follow_from_owasps_cwe_lists() {
        assert_eq!(json("sql_injection").unwrap(), serde_json::json!({"cwe": "CWE-89", "owasp": "A05:2025"}));
        assert_eq!(json("mass_disclosure").unwrap(), serde_json::json!({"cwe": "CWE-200", "owasp": "A01:2025", "owasp_api": "API4:2023"}));
        // Resource exhaustion is in no Top 10 category, only in the API list.
        assert_eq!(json("n_plus_1").unwrap(), serde_json::json!({"cwe": "CWE-1073", "owasp_api": "API4:2023"}));
        assert!(json("order_dependence").is_none());
        for c in TOP10 {
            assert!(TOP10.iter().filter(|o| o.cwes.iter().any(|x| c.cwes.contains(x))).count() == 1, "{} shares a CWE", c.id);
        }
        for k in KINDS {
            if let Some(a) = of(k).and_then(|s| s.api) {
                assert!(api(a).is_some(), "{k}: {a}");
            }
        }
    }

    #[test]
    fn the_table_says_what_a_manifest_without_labels_leaves_unchecked() {
        let bare = table(&Context::default(), &["crash", "mass_disclosure", "n_plus_1"]);
        let a01 = &bare[0];
        assert_eq!((a01.id, a01.found), ("A01", 1));
        assert!(a01.checked.contains(&"mass_disclosure"));
        assert!(a01.not_checked[Need::Identity.why()].contains(&"missing_owner_check"));
        assert_eq!(bare[9].found, 1);
        let all = Context { sinks: true, identity: true, owners: true, sensitive: true, output: true, scripts: true, http: true, effects: true };
        assert!(table(&all, &[]).iter().all(|r| r.not_checked.is_empty()));
    }
}
