# appfuzz and the OWASP Top 10

Security teams ask "what about the OWASP Top 10?". appfuzz answers per app:
every finding names its CWE and its OWASP category, and `review` lists each
Top 10 category with what it found, what it checked, what it could not
check and why, and what is up to the platform.

```json
{"kind": "sql_injection", "severity": "fail", "standards": {"cwe": "CWE-89", "owasp": "A05:2025"}}
```

```json
"owasp": [
  {"id": "A01", "name": "Broken Access Control", "found": 1,
   "checked": ["path_traversal", "mass_disclosure", "open_redirect", "…"],
   "not_checked": {"no identity labels: appfuzz doesn't know who the caller is": ["foreign_user_access", "missing_owner_check"]},
   "platform": "who may call which route (login, roles); appfuzz checks records of other users, not roles"}
]
```

A check that needs labels runs once the manifest has them: label the
platform's SQL parameter `sql` and the injection checks run on every
review. [AGENTS.md](AGENTS.md#4-labels-telling-appfuzz-what-text-means)
has the labels.

## OWASP Top 10 (2025)

**A01 Broken Access Control.** Another user's record shown, changed or
deleted (`missing_owner_check`), a user id taken from the request
(`foreign_user_access`), answers that depend on other users' records
(`tenant_leak`), more records in one response than the platform allows
(`mass_disclosure`), personal data or secrets where they must not go
(`pii_leak`, `secret_leak`), path traversal, SSRF, open redirects, a change
on GET or one the user didn't ask for, imports the platform didn't grant.
The platform's part: login and roles. appfuzz checks whose records an app
touches, not which user may call which route.

**A02 Security Misconfiguration.** CORS that lets another site read the
answer with the visitor's cookies (`permissive_cors`), a session cookie
without `HttpOnly` or `Secure` (`insecure_cookie`). The platform's part:
TLS, server headers and host settings.

**A03 Software Supply Chain Failures.** The platform's part: known-vulnerable
dependencies, builds and signing. appfuzz reviews the compiled app with
every dependency inside it, so a dependency that misbehaves shows up as the
app misbehaving.

**A04 Cryptographic Failures.** Secrets or personal data sent to a plain
`http://` URL (`cleartext_transport`), session tokens that stay the same
under other random seeds (`predictable_token`). The platform's part: TLS, keys and how
secrets are stored.

**A05 Injection.** SQL, shell, HTML, regex and header injection, text
escaped by hand, request or stored text in a page unescaped, request text
that becomes code in the page's scripts. Needs the platform's sinks
labelled (`sql`, `shell`, `path`, `url`, `html`, `regex`).

**A06 Insecure Design.** A Content-Security-Policy that lets scripts reach
other hosts (`weak_csp`), arguments outside what the platform accepts
(`invalid_host_argument`). The design itself is the team's: their
acceptance checks and the platform's business rules say what the app must
do, and appfuzz checks every run against them.

**A07 Authentication Failures.** Forged credentials that get in: a made-up
token, an unsigned JWT, a wrong signature (`auth_bypass`). The platform's
part: login, passwords, sessions and multi-factor authentication.

**A08 Software or Data Integrity Failures.** Scripts that run code fetched
from another host (`remote_code`), scripts from another host without an
integrity hash (`unpinned_script`), and the experimental hostile-code
checks (hidden text, encoded data, dormant code, unexpected destinations).
The platform's part: deploying the build that was reviewed.

**A09 Security Logging & Alerting Failures.** Request text whose line
breaks reach the log as they came, so a request can write log lines of its
own (`log_injection`). The platform's part: collecting logs, keeping them
and alerting on them.

**A10 Mishandling of Exceptional Conditions.** Crashes on a request, on an
odd value a host returned or at some clock time, internal error text shown
to users (`leaky_error`), errors ignored, work that continues after an
error, a change that stays when a later one fails (`partial_write`).

## OWASP API Security Top 10 (2023)

| Category | appfuzz finds |
|----------|---------------|
| API1 Broken Object Level Authorization | `missing_owner_check`, `foreign_user_access`, `tenant_leak` |
| API2 Broken Authentication | `auth_bypass`, `timing_unsafe_compare`, `predictable_token` |
| API3 Broken Object Property Level Authorization | `pii_leak` |
| API4 Unrestricted Resource Consumption | `mass_disclosure` (records per response), `over_budget`, `hang`, `n_plus_1`, `unbounded_read`, `cpu_blowup`, `memory_blowup`, growth with input |
| API5 Broken Function Level Authorization | platform: roles |
| API6 Unrestricted Access to Sensitive Business Flows | `repeated_write`; the rest is the team's acceptance checks |
| API7 Server Side Request Forgery | `ssrf`, `url_path_injection` |
| API8 Security Misconfiguration | `permissive_cors`, `weak_csp`, `insecure_cookie`, `cleartext_transport` |
| API9 Improper Inventory Management | `ungranted_import`, `ungranted_call` |
| API10 Unsafe Consumption of APIs | `stored_reflection`, `crash_on_host_value`, `hang_on_host_value` |

Resource exhaustion, timing leaks and uncontrolled recursion have CWEs that
no Top 10 (2025) category lists; their findings name the API category only.
Findings about speed and correctness (order dependence, chatty calls,
broken pagination) name no category.

## How the mapping is made

Each finding kind has one CWE. Its Top 10 category is the one whose
published CWE list contains that CWE
([owasp.org/Top10/2025](https://owasp.org/Top10/2025/), read 2026-11-07).
The API category is chosen per kind, from the
[API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)'s
descriptions.
