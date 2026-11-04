# appfuzz labels, vocabulary 1

Labels tell appfuzz what host functions, their parameters and their results
mean. appfuzz knows nothing about a platform. A platform team (or an AI
generating the manifest) writes labels into `appfuzz.toml`. Each label turns
on its own generators and checks. Every finding a label causes names that
label in its `detail.label`. If the finding is wrong, fix the label, not the
finding.

This file is the vocabulary. It is versioned. A manifest names the version
it is written in:

```toml
[app]
labels = "1"
```

appfuzz refuses a manifest written for a vocabulary it doesn't know.
Without `labels`, the current vocabulary applies. Without any labels,
appfuzz still runs the generic behavioral checks (AGENTS.md §6).

Labels sit under `[functions."<interface>#<function>"]`. The interface
version may be left out. A function the app doesn't import is skipped, so a
platform can label all of its functions once and use the same block for
every app. A label on a parameter or result path the function doesn't have
is an error.

## Parameters: `params = { <name> = "<label>" }`

| Label | Means | Finding when request or host text arrives with |
|-------|-------|------------------------------------------------|
| `sql` | SQL text | a quote intact: `sql_injection` (fail); quotes doubled or backslashed: `escaped_by_hand` (warn) |
| `path` | a file path | `../` intact: `path_traversal` (fail) |
| `shell` | a shell command | `;` or `$(` intact: `command_injection` (fail); `'\''` quoting: `escaped_by_hand` (warn) |
| `url` | a URL to fetch | control of the scheme or host: `ssrf` (fail); `../` intact in the path, so other endpoints of the API are reachable: `url_path_injection` (fail) |
| `html` | markup | `<i>` intact: `html_injection` (fail) |
| `regex` | a regular expression | `(` intact: `regex_injection` (warn) |
| `pii` | may receive personal data | no `pii_leak` for it |
| `secret` | may receive secrets | no `secret_leak` for it |
| `user-id` | names a user; must be the caller | a value that is not the caller's identity: `foreign_user_access` (fail) |

The parameter must hold text (`user-id`: text or a number). Canaries in request fields and host strings
carry `<i>'"../;$(x)`, and the fuzzer adds attack strings for each sink.

## Results: `result = "<label>"` or `result = { <path> = "<label>" }`

A path is dot-separated field names. It goes through lists, options and
the `ok` side of results. An empty path, `result = "secret"`, is the whole
result.

| Label | Means | Check |
|-------|-------|-------|
| `untrusted` | the default: text that must not reach sinks or HTML unescaped | `stored_reflection`, sink findings |
| `html` | trusted markup | no `stored_reflection` or `html_injection` for it |
| `pii` | personal data | `pii_leak`: fail in logs, error pages, and host parameters not labelled `pii`; warn in a URL or header; nothing in an ordinary page, unless `[entry] no_pii = true` (below) |
| `secret` | a secret | `secret_leak`: fail anywhere in the output, logs, or host parameters not labelled `secret` |

| `identity` | who the caller is (a user id) | the run's caller for `user-id` and `owner` |
| `owner` | who the record that holds this field belongs to | `missing_owner_check` (fail): another user's record shows in a page with a status below 400 |

Generated values at `pii` and `secret` paths are traceable markers
(`p…@mail.example`, `sk_…`). `identity` and `owner` paths hold text or
numbers. Generated identities are the run's caller, and about half the
generated owners are the caller too. An app that checks ownership shows
the record in some runs and refuses it in others.

A value the request itself carries is not a leak: the user typed it.
`reflection` covers request text. Values shorter than four characters are
not traced. One finding covers all values from the same function and path
in the same place; `detail.count` says how many (the emails of 37 people
in one page are one finding with `count: 37`).

### No personal data in the output: `[entry] no_pii = true`

Some exports have no business returning personal data: a dashboard of
counts, a menu, a status. They may still read it, to count or filter.

```toml
[entry]
no_pii = true
```

With it, a value from a `pii` path anywhere in the export's output is
`pii_leak` (fail): in the body and headers when `[entry] output` maps them,
and in every string of the result otherwise, at any depth
(`detail.at = "ok.rows[1].contact"`). Encoded forms (`encoded_flow`) in the
body fail too. Calling functions that return personal data stays allowed;
which functions an app may call is the platform's business. The caller's
own data counts as well: an export that shows the user's own profile
doesn't get `no_pii`.

## Identity

The caller's identity comes from a host result labelled `identity` (for
example `users#current`, `result = { id = "identity" }`), or from a request
field with the role `identity` (`[entry] fields = { user = "identity" }`),
when the platform puts the caller in the request. Without either, the
identity labels do nothing.

| Finding | When |
|---------|------|
| `foreign_user_access` (fail) | a `user-id` argument is not the caller: it comes from a request field, or the app never asked who the caller is |
| `missing_owner_check` (fail) | a page with status below 400 shows text of a record whose `owner` is not the caller (text the caller's own records also hold doesn't count) |

```toml
[functions."acme:web/users#current"]
result = { id = "identity" }

[functions."acme:web/orders#for-user"]
params = { user-id = "user-id" }
result = { owner = "owner" }

[functions."acme:web/orders#get"]
result = { owner = "owner" }
```

## Effects: `effect = "<effect>"`

What a call does to the world.

| Effect | Means |
|--------|-------|
| `read` | reads; no change |
| `write` | creates or changes platform data |
| `delete` | removes platform data |
| `external` | acts outside the platform: sends mail, charges a card, posts a message |

`write`, `delete` and `external` are *changes*. With them:

| Finding | When |
|---------|------|
| `write_on_safe_method` (fail) | a GET, HEAD or OPTIONS request makes a change; a link, a prefetch or a crawler can trigger it |
| `repeated_write` (fail) | a change that is not `idempotent` is made twice with the same arguments in one request, after the first one worked (and not because a host list held the same element twice) |
| `retry_storm` (fail, else warn) | a failed change that is not `idempotent` is retried again and again; it may have happened anyway |
| `n_plus_1`, `input_amplification` (fail, else warn) | one change per element of a host list or per unit of a request field |
| `partial_write` (warn) | one change succeeds, a later different change fails, and the response still says all went well: a status below 400, and the failed call's error text neither in the body nor in a header (a redirect's `location`, percent-encoded there). appfuzz checks this once more with another error text, so an empty error the app passes on counts as told |

`idempotent = true` (only with a change) says the same call twice is
harmless, for example a write that sets a value rather than adding one. It
turns off `repeated_write` and the stricter `retry_storm`.

## Batches: `batch_of = "<interface>#<function>"`

This function does for many at once what `<function>` does for one, for
example `items#get-many` for `items#get`. If the app calls `<function>` in
a loop, `n_plus_1`, `input_amplification` and `chatty` name the batch
function, and the n+1 is a fail. The batch function need not be imported:
it's enough that the platform offers it.

## Errors for users: `user_errors = true`

The function's error texts are written for the people using the app, for
example "Bookings start between 08:00 and 16:00", and the platform says
the app may show them as they are. Showing them is then no `leaky_error`,
and a page with status 200 that shows one is no `inconsistent_response`.
Leave it off for functions whose errors carry internals (SQL, paths, stack
traces).

```toml
[functions."acme:web/bookings#create"]
user_errors = true
```

Without it, a host error text in the page counts only if the page doesn't
show the same text when the error says something else: appfuzz runs the
request once more with the error text changed. A generated error text that
happens to be a word the app writes itself (a CSS class, a heading) is not
reported.

## The response: `[entry] result = { <path> = "<label>" }`

What the platform allows in the export's result, by field path (as in
`output`; `headers.location` is the `location` pair in a header list).

| Label | Means | Finding |
|-------|-------|---------|
| `html:no-scripts` | no script may run from this markup | `script_in_output` (fail): a `<script>`, `<object>`, `<embed>`, an iframe `srcdoc`, an event handler of any framework (a name like `on…`, `@…`, `…on:…`, `(…)`), a `js:` value, or a `javascript:` (or HTML `data:`) URL in any attribute, read with entities decoded; (warn) a value that looks like code (`f(…)`, `=>`) in an attribute of no standard meaning |
| `html:safe` | `html:no-scripts`, and no request the user didn't ask for | also `unsafe_action` (fail): a meta refresh; a form, a load (`src`, CSS `url()`, a stylesheet) or a URL in an attribute of no standard meaning to another host or to a sensitive route; such a URL on an element that says it fires by itself (a word like `load`, `every`, `init`, `intersect`, `poll` in another attribute or in the attribute's name) |
| `url:local` | a path on the app's own host | `open_redirect` (fail) when request text makes it point elsewhere (`//host`, `/\host`, a scheme); `non_local_url` (warn) when the app points elsewhere by itself |

`sensitive_paths = ["/admin"]` in `[entry]` lists the routes no `html:safe`
markup may send a request to, the route and everything below it. Ordinary
links (`<a href>`) are allowed anywhere: the user clicks them.

appfuzz knows no framework. Standard HTML attributes count by their
meaning (`href` a link, `action` a form, `src` a load). Every other
attribute, `data-*` and the attributes of htmx, Alpine, Turbo and the
like, counts by the shape of its value: text that looks like a URL (a
scheme, `//`, a path, a host) is a request some code may make. So are
URLs in string literals of inline scripts and JSON, in CSS, in pieces
of several attributes, and in response headers. Entities, `%` and `\x`
escapes are undone first.

```toml
[entry]
result = { body = "html:safe", "headers.location" = "url:local" }
sensitive_paths = ["/admin", "/settings"]
```

With output labels the fuzzer also tries `//evil.example/`,
`javascript:alert(1)` and markup with event handlers in request fields.

## Host argument requirements and guest input domains

`[functions.KEY].param_values` declares platform requirements on actual host-call
arguments, by parameter and nested field path. Violations produce
`invalid_host_argument` fails, including when the host returns an ordinary error.
Values are checked before trace shortening; host rules still determine responses
and effects. Optional `value_source` records the platform requirement source.

`[entry].input_values` describes what the guest should accept. Other values can
still arrive. Saved single-run acceptance checks can select `input_class`
(`valid`/`invalid`), optional `input_fields`, exact request-field `when` matches,
and `forbid_effects` (`write`, `delete`, `external`, `read`). Expected behavior
remains an explicit output expectation or property. Unexercised classes,
platform-filtered cases and missing selectors are incomplete, never passing.

These two new maps accept a constraint string or an array of conjunctive
constraints. Besides the vocabulary below, they support `required` (presence),
`bytes:a..b` (UTF-8 byte length), and `format:uuid` (8-4-4-4-12 hex digits; nil is
syntactically valid). Existing `len` still counts Unicode scalars or list
elements. Combine `required` with `len:1..` for nonempty values. New domains keep
numeric integer bounds exact. Dates use years 0001–9999 with real calendar
validation; time/date-time use local hours/minutes and optional seconds, without
offsets, fractions or leap seconds. Integer text allows one optional minus sign
and one or more ASCII digits. Types are never inferred from names or values.
See [REFERENCE.md](REFERENCE.md#declared-value-contracts) for paths, examples and replay semantics.

## Value constraints: `values = { <path> = "<constraint>" }`

What the platform promises about a value. On a host function, the paths
are result paths: the host never returns anything else. In `[entry]`, the
paths are request fields: the platform rejects other requests before the
app sees them.

| Constraint | Means |
|------------|-------|
| `range:a..b` | a number, or text holding one, from `a` to `b` (either end may be left out: `range:0..`) |
| `len:a..b` | characters of text, or elements of a list |
| `enum:x,y,z` | one of these |
| `format:date`, `format:time`, `format:datetime`, `format:email`, `format:int`, `format:uuid` | `2026-11-02`, `10:00`, `2026-11-02T10:00:00`, `a@b.c`, `-12`, `00000000-0000-4000-8000-000000000001` |
| `unique`, `unique:a,b` | no two elements of a list alike, as a whole or by these fields together: a unique key of the platform's database |

Generated host values keep to the constraints, and so do plan values (the
host keeps its promises). Fuzzed requests mostly keep to them, and `scale`
doesn't grow a field past its range. A run whose request breaks a
constraint has its findings lowered to info, with `detail.invalid_request`.
A crash on a value the platform never produces is not a finding; a crash
on one it does produce stays a fail.

A `unique` list never holds the same element twice: generated and plan
values drop the repeats, and the duplicate probe skips the function, so
there is no `duplicate_sensitivity` for a duplicate the database can't
hold. Use the path of the list; `""` is the whole result.

```toml
[entry]
values = { "query.days" = "range:1..31", "query.sort" = "enum:name,date" }

[functions."acme:web/items#all"]
values = { score = "range:0..100", name = "len:1..80" }

[functions."acme:web/bookings#list-for-day"]
values = { "" = "unique:pod_id,date,hour" }
```

## Rules: `rules = [ { when = {…}, return = … } ]`

What the host always answers for some arguments: the platform's own
business rules. A rule has the shape of a plan rule (`when` with
matchers, then `return`, `generate` or `trap`), but it comes before
every plan and before the fuzzer: the host keeps its promises. The first
matching rule decides; calls no rule matches are planned or generated as
usual. A finding then is about what the real platform would do, not
about a value it never returns.

```toml
[functions."acme:web/bookings#create"]
rules = [
  { when = { hour = { not = { range = [8, 16] } } }, return = { err = "closed" } },
  { when = { subject = { regex = "^\\s*$" } }, return = { err = "subject is required" } },
]
```

Matchers: a plain value (equal), `{ regex = "…" }`, `{ range = [lo, hi] }`,
`{ contains = "…" }`, `{ any = true }`, `{ not = <matcher> }`. A rule that
names a parameter the function doesn't have is an error.

A rule can also label the results for its arguments, with `result` in
the shape of a function's `result`. One function can then return a
secret for some arguments and plain text for others:

```toml
[functions."fermyon:spin/variables#get"]
rules = [
  { when = { name = "api-token" }, result = "secret" },
  { when = { name = "greeting" }, return = { ok = "Hello" } },
]
```

The first rule with `result` whose `when` matches gives the call's
labels; calls it doesn't match keep the function's own. A rule with
`result` and no `return`, `generate` or `trap` only labels: the answer
comes from the next matching rule, the plan or the fuzzer. Labels belong
in the manifest; a plan rule with `result` is an error.

## Request fields: `[entry] fields = { <path> = "<role>" }`

| Role | Means |
|------|-------|
| `clock.date`, `clock.time`, `clock.datetime` | filled from the virtual clock, varied with it |
| `http.method`, `http.path`, `http.query`, `http.form` | the parts of an HTTP request; used for crawling and for `write_on_safe_method`. Without roles, fields named `method`, `path`, `query`, `form` count |
| `identity` | the caller's user id, put in the request by the platform |
