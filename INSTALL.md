# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no
address and no service, and adding a copy touches neither the node nor the configuration. Usually
`placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.action` queue, audit, log, profile generations |
| Controller | yes | sends profiles as generations |
| Buffer Redis | for conditions on headers, cookies, arguments | request snapshot by locator |
| Internal Redis | for dataset conditions | mirror of keeper's active datasets |
| `keeper` | for dataset conditions and writes | owns dataset contents |
| `geo` | for writes with `write: net` / `net_all` / `asn` | announcements and AS composition by address |

This inspector has the least work of all: path and method come in the message, and one copy per
installation is the usual layout.

## Settings

The main ones are below; the full table is in [README.md](README.md#settings).

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222`; `nats://nats:4222` in the image | bus |
| `REDIS_URL` | from `inspector.conf` | buffer: request objects for conditions |
| `REDIS_INTERNAL_URL` | from `inspector.conf` | internal Redis: dataset mirror and the bodies of static lists. Empty falls back to the buffer with a warning in the log |
| `WAF_ACTION_SUBJECT` | `waf.req.action` | subscription |
| `WAF_ACTION_NAME` | `action` | name in the inspector registry |
| `WAF_ACTION_PROFILES` | `/app/profiles` in the image | profiles shipped in the image; generations go to `WAF_ACTION_DATA` |
| `WAF_ACTION_GEO_ADDR` | empty | network directory (`host:port`). Empty makes writes with `write: net`, `net_all` or `asn` answer `ACTION_GEO_UNAVAILABLE` |
| `WAF_ACTION_LOG` | `info` | starting log level; the panel changes it live |

## Docker Compose

```yaml
services:
  inspector-action:
    image: placitum/action
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_ACTION_SUBJECT: waf.req.action
      WAF_ACTION_NAME: action
      WAF_ACTION_GEO_ADDR: geo:50051
    depends_on: [nats, redis, redis-internal]
```

## Place on the wave

Neighbours on the same wave do not see actions. An inspector that should hear `action` must be on a
**later** wave; that is set on the route, not in the profile. On the same wave the requests go
nowhere, and the module warns about it in the log.

## Checking

The image has a `HEALTHCHECK`: `action-probe` sends a request over the bus the way the module does
and waits for the answer. The presence frame is on the bus as well:

```sh
nats sub 'WAF_STATUS.inspector.action.>' --count 1
```

A healthy start logs `profile loaded` for every profile, `object store connected`, `internal redis`
with the address, `connected` with the queue name and `desired watch on`.

## Pitfalls

- **No verdict except `allow`.** Its own failure (a broken message, an unsupported version,
  overload, an unavailable buffer) is `verdict: error` with an `ACTION_*` code, not a silent
  `allow`. That does not make it a gate: an error of a passive inspector does not break the wave.
- **Header conditions without the buffer** treat the object as unavailable: the rule does not
  fire, and the audit shows why.
