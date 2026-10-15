# API reference

The public surface of `actix_guard_rs` `1.0.0`. The full crate documentation
is also in `src/lib.rs` (build it with `cargo doc --open`).

## Middleware

### `GuardTransform`

The actix-web middleware entry point. `GuardTransform` implements
`Transform<ServiceRequest>`; register it with
`App::wrap` (or a `web::scope`'s `wrap`) so every request routed after it is
screened before it reaches the wrapped service.

```rust
use actix_guard_rs::{default_config, GuardTransform};
use actix_web::{App, web};

let app = App::new().wrap(GuardTransform::new(default_config())).route(
    "/",
    web::to(|| async { "ok" }),
);
```

Constructors and builders:

| Method | Description |
|---|---|
| `GuardTransform::new(config: DetectConfig)` | Build a transform from an engine `DetectConfig`. The body buffering cap starts at `config.max_full_scan_bytes` |
| `GuardTransform::with_defaults()` | Build a transform with `default_config()` |
| `.with_body_cap(body_cap: usize)` | Replace the body buffering cap, in bytes. A body larger than the cap is rejected with `413`. A cap of `0` rejects every request that carries a non-empty body |
| `.with_ip_gate(ip_gate: IpGateConfig)` | Install the global IP gate (see below) |

The transform clones into a per-worker `GuardService`; actix Web builds its
service tree per worker on single-threaded event loops, and the wrapped
service is shared through an `Rc`, so this never crosses threads.

### `GuardService`

The `Service` produced by `GuardTransform`. It screens a `ServiceRequest` by
running one engine call per request view and, on a clean pass, hands the next
service a rebuilt request whose body is byte-identical to what the client
sent (actix Web consumes the payload as it is read, so the middleware buffers
it under the cap and rebuilds the request).

## Configuration

### `default_config()`

Returns the reference default `DetectConfig`. The engine's `DetectConfig`
carries no `Default` impl, so the adapter pins the ecosystem defaults here;
they are the values the engine conformance corpus records:

| Knob | Value |
|---|---|
| `max_content_length` | `10_000` |
| `max_full_scan_bytes` | `262_144` |
| `preserve_attack_patterns` | `true` |
| `semantic_threshold` | `0.7` |
| `threat_score_threshold` | `1.0` |

### `DetectConfig`

Re-exported from `guard_core_engine::detect`. Fields:

| Field | Type | Meaning |
|---|---|---|
| `max_content_length` | `usize` | Semantic budget and truncation budget |
| `max_full_scan_bytes` | `usize` | Preprocessor full-scan cap (also the default body cap) |
| `preserve_attack_patterns` | `bool` | Keep attack patterns in the processed view |
| `semantic_threshold` | `f64` | Semantic analysis threshold |
| `threat_score_threshold` | `f64` | Threat score threshold for a verdict |

A custom configuration:

```rust
use actix_guard_rs::DetectConfig;

let config = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
};
```

## Behavior

### What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not scanned.

### The IP gate: `IpGateConfig`

Built with `IpGateConfig::new(whitelist, blacklist, exempt_ips)`, which fails
closed on an invalid entry (`IpGateError` names the list and the entry):

```rust
use actix_guard_rs::{GuardTransform, IpGateConfig};

let gate = IpGateConfig::new(
    [] as [&str; 0],
    ["203.0.113.9"],
    ["198.51.100.7", "198.51.100.16/28"],
)
.expect("valid lists");
let transform = GuardTransform::new(actix_guard_rs::default_config()).with_ip_gate(gate);
```

Evaluation order mirrors the reference engine: with a non-empty `whitelist`,
an IP matching neither the whitelist nor `exempt_ips` is denied; otherwise a
`blacklist` hit is denied. Both denials answer `403 Forbidden` with
`Forbidden` before body buffering. The client IP is the resolved client (the
peer address, or the forwarded client behind a trusted proxy, see
`GuardTransform::with_client_policy`); a request without one is not
attributed, the gate does not run, and detection still screens it (a config
built with `from_security_config` rejects it under `fail_secure`). A passed request gets an
`IpGateDecision { is_whitelisted, is_exempt }` inserted into its request
extensions so downstream handlers can read the skip state.

**exempt_ips vs whitelist.** `exempt_ips` is noise reduction for
known-friendly automation (monitoring probes, VPN egress, a partner's
server), not immunity: it sets the same skip state a whitelist match sets but
never adds a deny path and never opens the whitelist gate. The blacklist,
route rules, and detection still apply to exempt IPs - an attack payload from
an exempt IP is still `400 Suspicious activity detected`. The stateful stages
(`GuardTransform::with_rate_limiting`, `GuardTransform::with_ip_banning`) skip
exactly what the reference skips for a whitelist match
(`is_whitelisted || is_exempt`): rate limiting, violation counting, and
banning. Detection never skips anything.

### The rate limiter: `RateLimiter`

```rust
use actix_guard_rs::{GuardTransform, RateLimitConfig, RateLimiter};

let limiter = RateLimiter::new(RateLimitConfig {
    enable_rate_limiting: true,
    rate_limit: 30,
    rate_limit_window: 10,
    ..RateLimitConfig::default()
})
.expect("valid config");
let transform =
    GuardTransform::new(actix_guard_rs::default_config()).with_rate_limiting(limiter);
```

The limiter's constructor fails closed on a zero limit or window. Installed
with `GuardTransform::with_rate_limiting`, it runs after the IP gate and the
ban stage, before body buffering and detection: a crossing answers
`429 Too Many Requests` with `Retry-After: <window seconds>`. With
`enable_rate_limit_auto_ban` on and IP banning configured, every crossing
counts one `rate_limit` violation toward the auto-ban engine; the response
stays `429` and the ban bites on the next request. Requests without a peer
address cannot be attributed and are not rate limited; detection still
screens them. The limiter is shared across workers through an `Arc`, and its
handles are cheaply clonable, so out-of-band handles work alongside it.

### The ban stage: `IpBanManager` + `IpBanConfig`

```rust
use actix_guard_rs::{GuardTransform, IpBanConfig, IpBanManager, ThreatBanEntry};

let manager = IpBanManager::new();
let config = IpBanConfig::new(
    true,
    10,
    3600,
    [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
)
.expect("valid config");
let transform =
    GuardTransform::new(actix_guard_rs::default_config()).with_ip_banning(manager, config);
```

The config constructor fails closed on an invalid `threat_ban_config`
entry. Installed with `GuardTransform::with_ip_banning`, the ban check runs
before the limiter: a live ban answers `403 Forbidden` (`IP address banned`)
and banned traffic never consumes rate budget. Every detected threat counts
its categories per client IP (the reference pipeline's suspicious-activity
stage), and a crossed `threat_ban_config` entry or the flat
`auto_ban_threshold` bans on the spot, answering `403 Forbidden`
(`IP has been banned`); without a crossing the block keeps the
`400 Bad Request` (`Suspicious activity detected`) shape.
`config.enable_ip_banning = false` counts violations but never bans.
Whitelisted and exempt IPs are never counted, so they can never be
auto-banned. The store pair is shared across workers through an `Arc`.

### Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough. Engine panics are caught
with `catch_unwind` on the worker thread (note that `panic = "abort"` in a
release profile disables that recovery).

### Constants

Re-exported refusal message bodies:

| Constant | Value |
|---|---|
| `BLOCKED_MESSAGE` | `"Suspicious activity detected"` |
| `FORBIDDEN_MESSAGE` | `"Forbidden"` |
| `BANNED_MESSAGE` | `"IP address banned"` |
| `ACTIVITY_BANNED_MESSAGE` | `"IP has been banned"` |
| `RATE_LIMITED_MESSAGE` | `"Too many requests"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`.

`IpGateConfig`, `IpGateDecision`, `IpGateDenial`, `IpGateError`, and
`IpGateVerdict` are re-exported from `guard_core_engine::ip_gate`.

`RateLimiter`, `RateLimitConfig`, `RateLimitConfigError`, and
`RateLimitDecision` are re-exported from `guard_core_engine::rate_limit`.

`IpBanManager`, `IpBanConfig`, `IpBanConfigError`, `BanError`, `BanRecord`,
`Clock`, `ResolvedBan`, `ThreatBanEntry`, and `ViolationCounters` are
re-exported from `guard_core_engine::ip_ban`. A `DetectVerdict` carries `is_threat`, a
`threat_score`, and the list of `Threat` findings (regex or semantic).
