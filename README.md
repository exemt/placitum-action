# Placitum action inspector

English · [Русский](README.ru.md)

A pure sender of the action channel. It checks nothing, blocks nobody and has no verdict except
`allow`: it looks at the route and tells its neighbours what to do. It can soften `modsec` on a
trusted path, tell captcha that a client loads static files, signal to let a service request through,
or signal the module to add or remove score on the route (`do: score`), mark the record, or override
the log and archive. What to say can depend on the request: a profile has **conditions**,
comparisons of request values with datasets and text, and every rule runs always, if a condition
holds, or unless it holds.

Two properties set it apart from checking inspectors:

- **No verdict except `allow`.** It checks nothing and adds nothing to the score; it moves score on
  the route with a `score` request that the module executes. Its own failures (a broken message, an
  unsupported schema version, overload, a panic, an object the buffer did not return) are
  `verdict: error` with an `ACTION_*` code, so a failing process does not look healthy. An error of
  a passive inspector does not break the wave.
- **It runs on an earlier wave than its receivers.** Neighbours on the same wave do not see its
  actions, so an inspector that should hear `action` must be on a later wave. Actions are sent only
  in the request phase; other phases get `allow` without actions (`ACTION_IDLE`).

## Profiles

Profiles are files `<name>.yaml` in `WAF_ACTION_PROFILES` (`./profiles` by default). The route names
a profile with `profile=`; an unknown name gets `verdict: error` with `ACTION_UNKNOWN_PROFILE`. The
directory is reread on the fly; a broken edit does not replace the live snapshot.

The controller can roll profiles out as well: the panel keeps them, and publishing puts a manifest
into the `WAF_DESIRED` KV under `policy/action`. The inspector unpacks the generation into
`WAF_ACTION_DATA` (`<profiles>.applied` by default) as flat `<name>.yaml` files and switches the
loader to it; a broken generation is not applied and shows as `apply_failed` in the presence frame.

```yaml
mode: enforce            # printed by the controller; whether the inspector runs is decided by the route
conditions:              # named conditions; rules reference them by name
  - name: trusted_key
    all:                 # lines joined with AND: the condition holds when every line matches
      - value: $http_x_api_key     # a request value, written as in the module's if
        op: in                     # in | not_in against a dataset; eq | ne against text
        dataset: api_keys          # a list of the space: dynamic (keeper mirror) or static (static: true)
      - value: $request_method
        op: eq
        text: POST
  - name: from_office
    any:                 # lines joined with OR: the condition holds when any line matches
      - value: $remote_addr
        op: in
        dataset: office_nets
        type: cidr                 # address dataset: address comparison (printed by the controller)
      - value: $http_x_forwarded_for
        op: in
        dataset: office_nets
        type: cidr
  - name: risky
    any:
      - cond: trusted_key          # reference to another condition: is means true, is_not false
        op: is_not
      - cond: from_office
        op: is_not
rules:
  - name: calm-modsec-healthz   # the name shows up in the log and audit, not on the wire
    match:                       # every given block must match (AND)
      path_prefix: "/healthz"    # path prefix, without the query string
      suffixes: [".json"]        # path suffixes, any of them; case-insensitive
      static: true               # plus the built-in static file extensions
      methods: [GET, HEAD]       # empty means any method
    actions:                     # one or more
      - to: modsec               # a recipient is required for requests to a neighbour
        do: threshold            # challenge | threshold | skip | reauth | note | mutate | control verbs
        apply: request           # filled from the dictionary where there is no choice
        delta: -50               # threshold only: percent, −100…+900; minus is a discount, plus stricter
        code: ROUTE_TRUSTED      # [A-Z][A-Z0-9_]*, up to 64 bytes
  - if: trusted_key              # actions are sent when the condition holds
    actions:
      - to: modsec
        do: skip
        code: API_KEY_TRUSTED
  - unless: from_office          # actions are sent when the condition does not hold
    actions:
      - do: score                # score on the route: executed by the module, no to field
        apply: request
        value: 30                # signed, −100…100, not zero: minus removes accumulated score
        code: OUTSIDE_OFFICE
  - if: risky                    # a write to a live dataset: outlives the request
    actions:
      - list: blocked            # an active dataset of the space; no to and do
        write: net               # addr | net | net_all | asn; empty means addr
        ttl: 1h                  # required, at least a second
        code: ACTION_RISKY       # reason; empty means ACTION_LIST
```

Rules accumulate and none is terminal: every matching rule fires, actions add up in the order of the
rules, and the module keeps the limit (`waf_actions_max`). An empty `match` matches every request of
the profile, since the route already selected the profile; a rule without `if` or `unless` always
works. Loading repeats the module's validation: an unknown verb, an axis that does not fit the verb,
numbers out of range, a bad code, a recipient on a score or dataset action, a reference to an
undeclared condition, or `if` and `unless` together reject the whole profile.

An action can also be a **write to a live dataset**: `list` and `ttl` (plus `write` and `code`),
without `to` and `do`. The subject goes to the active dataset as a keeper event
`waf.sets.<set>.event`, and from then on the local layer on the node or the address inspector cuts
it off before the bus. `write` takes the same four kinds as every sender: `addr` is the client
address (the default), `net` the effective announcement, `net_all` every announcement covering the
address, including wide foreign ones, and `asn` the whole autonomous system. The batch goes to
keeper in one frame with one expiry and one reason (`ACTION_LIST` without `code`): all or nothing.
For `net`, `net_all` and `asn` the inspector asks the network directory over gRPC (`WAF_ACTION_GEO_ADDR`)
synchronously, within the message budget. If the network directory is needed and silent, the answer is
`verdict: error` with `ACTION_GEO_UNAVAILABLE`, the route's `waf_exception` chooses the outcome, and
address writes of the same request still go out. A write fires on every matching request and
extends the expiry: the inspector keeps no memory of what it already wrote, so filter repeats with a
dataset or a condition in front. The controller allows writes only to active datasets of the space,
and `net`, `net_all` and `asn` only to address datasets.

### Conditions

A condition is the same as `if <value> in|not in <dataset>` on an inspector call in a route, but the
inspector evaluates it and can also compare with text. Condition lines combine with AND (`all`:
every line matches) or OR (`any`: at least one), exactly one of the two keys. A line can also
reference another condition of the profile (`cond: <name>`, `op: is | is_not`), so AND inside OR
and any depth are built from flat named conditions. Forward references are fine; self references
and cycles are not, and a cycle rejects the profile at load time. Evaluation is lazy: AND stops at
the first false line, OR at the first true one, and every condition is evaluated at most once per
request however many references it has. Matching works as in the module: `in` and `eq` hold when at
least one value matches, `not_in` and `ne` when none does. An empty value is simply "not in the
dataset": a missing cookie is not among the trusted ones either, so `not_in` on it holds. A dataset
the mirror has not received yet and an object the route does not capture behave the same way:
missing data never turns into a match.

A profile rolled out by the controller keeps one line per condition: in the panel, AND and OR are
groups in a rule's When. The controller prints those groups as conditions of their own, `rule-N` for
the When of rule N and `rule-N.M` for its group M, so they show up in `engine.conditions` next to
the named ones.

| Value | Source | What it gives |
| --- | --- | --- |
| `$uri`, `$request_uri`, `$host`, `$request_method`, `$scheme`, `$remote_addr` | message | the field as is; `$request_uri` is the path with the query string from the buffer |
| `$http_<name>`, `$cookie_<name>`, `$arg_<name>` | buffer | the first occurrence; header names as in nginx (lower case, `-` becomes `_`), cookie and argument names exact |
| `$waf_request_headers.<name\|*>`, `$waf_request_cookies.<name\|*>`, `$waf_request_args.<name\|*>` | buffer | every value; `*` means every pair of the object |
| `$waf_var.<name>` | `vars` section of the message | a standard module field (`user_agent`, `referer`, `xff`, …) or `waf_var`; sent according to `vars=` of the declaration |

Headers, cookies and arguments come from the route snapshot (`waf_capture`, `headers args` by
default). The inspector fetches them from the buffer lazily, for the first condition that needs
them, and once per request; a profile without such conditions never touches the buffer. When the
route does not capture headers, `$http_<name>` is read from `vars` if the field is there
(`user_agent`, `referer`, `x_forwarded_for` as `xff`, `accept_language`, `origin`, `content_type`,
`accept`). Arguments are parsed like in the module selector: percent-decoding, `+` becomes a space;
cookies are trimmed and unquoted, without decoding. If an object existed but could not be fetched
(the buffer did not answer, the key is gone), that is an inspector failure: `verdict: error` with
`ACTION_STORE_ERROR`, and `waf_exception` of the inspector class chooses the outcome.

A dataset is a list of the space, dynamic or static. A dynamic (active) list is mirrored over the
keeper protocol (`waf.sets.<set>`) and requested with every profile snapshot, so the first request
does not wait for a snapshot. A static list (`static: true`) comes with the generation: the manifest
names it with the sha256 of its body, the inspector reads the body from the internal Redis
(`waf.blob.<hex>`), checks the hash and keeps it next to the profiles (`profiles/.lists/<name>.txt`,
one value per line). A profile whose static list is not there does not load. `type: cidr` marks an
address dataset: the value must be an address, and the comparison works on addresses and prefixes.
`hash: md5` marks a dataset with `hash=md5`: the value is hashed before the lookup. The controller
prints all three keys from the dataset catalog; in hand-written files copy them from the dataset
definition.

The `kind=inspector` event shows what was evaluated: `engine.conditions` maps condition names to
true or false for the conditions that were reached, and `engine.notes` says where data was missing
(`unavailable`: the object or section is unavailable, `not_ready`: the dataset has not reached the
mirror yet, `not_addr`: the value is not an address).

A reminder about signs: `delta` is a percentage of the receiver's coefficient (multiplier
`1 + delta/100`); minus is a discount, plus makes the client's behaviour more expensive. `value` is
a percentage of the receiver's counter scale, −100…+100: plus adds a share of the trigger threshold
(+100 fills it at once), minus removes a share of what was accumulated (−100 resets it, never below
zero). Only a receiver with an acceptance rule for this sender by name applies the sign.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus; a comma-separated list |
| `REDIS_URL` | `url` from `inspector.conf` | buffer: headers and query string for conditions. Empty means such objects are unavailable, with a warning at start |
| `REDIS_INTERNAL_URL` | `internal` from `inspector.conf` | internal Redis: the dataset mirror reads keeper packages and snapshots from it, and the bodies of static lists come from it. Empty falls back to the buffer with `internal redis falls back to the buffer` in the log; with both empty datasets stay empty |
| `WAF_ACTION_SUBJECT` | `waf.req.action` | subscription |
| `WAF_ACTION_NAME` | `action` | name in the inspector registry |
| `WAF_ACTION_QUEUE` | the name | NATS queue group |
| `WAF_ACTION_PROFILES` | `./profiles` | profile directory |
| `WAF_ACTION_DATA` | `<profiles>.applied` | where rollout puts the applied generation |
| `WAF_ACTION_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_ACTION_RELOAD_EVERY` | `1s` | how often to check the profile directory |
| `WAF_ACTION_GEO_ADDR` | empty | network directory gRPC address (`host:port`) for `write: net`, `net_all` and `asn`. Empty makes such writes answer `ACTION_GEO_UNAVAILABLE`; address writes work |
| `WAF_ACTION_GEO_TIMEOUT` | `500ms` | how long to wait for the network directory on a miss, within the message budget |
| `WAF_ACTION_GEO_NEG_MAX` | `0` | negative cache limit of the network directory client; `0` means the default of one million |
| `WAF_ACTION_WORKERS` | number of CPUs | parallel workers |
| `WAF_ACTION_QUEUE_DEPTH`, `WAF_ACTION_QUEUE_FULL`, `WAF_ACTION_QUEUE_EXPAND` | from `inspector.conf` | queue overrides |
| `WAF_ACTION_RESERVE_MS`, `WAF_ACTION_MIN_BUDGET_MS` | `1`, `1` | deadline reserve and minimum budget of a message, in milliseconds |
| `WAF_ACTION_VERSIONS` | `2` | accepted message schema versions; others get `verdict: error` with `ACTION_UNSUPPORTED_VERSION` |
| `WAF_ACTION_LOG` | `info` | starting log level: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert`; the `settings` block of a generation changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP`, `WAF_LOG_WRITER` | `on`, host name | whether the process log goes to the bus, and its writer name |

The image sets `NATS_URL=nats://nats:4222`, `WAF_ACTION_PROFILES=/app/profiles` and
`WAF_ACTION_DATA=/var/lib/waf/action`.

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
