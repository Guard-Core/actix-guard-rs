<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Application-layer security middleware for [actix-web](https://github.com/actix/actix-web) 4, powered by the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/Guard-Core).</strong>
</p>

<p align="center">
    <a href="https://crates.io/crates/actix-guard-rs">
        <img src="https://img.shields.io/crates/v/actix-guard-rs?color=0080ff" alt="Crates.io version">
    </a>
    <a href="https://guard-core.github.io/actix-guard-rs/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/actix-guard-rs/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/actix-guard-rs?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Actix%20Web-0B0B0B.svg?style=flat" alt="Actix Web">
    <a href="https://crates.io/crates/actix-guard-rs">
        <img src="https://img.shields.io/crates/d/actix-guard-rs" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/actix-guard-rs/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---


## Ecosystem

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

___

## Documentation

📚 **[Documentation](https://guard-core.github.io/actix-guard-rs/latest/)** - full technical documentation for this package.

🛡️ **[Guard Core](https://guard-core.github.io/guard-core/latest/)** - the engine's reference documentation.

🤖 **[Monitoring Agent Integration](https://github.com/Guard-Core/guard-agent)** - monitor your Guard instance with a monitoring agent.
___

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard), [djapi-guard](https://github.com/Guard-Core/djapi-guard), [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) with adapters for [tower](https://github.com/Guard-Core/tower-guard-rs), [axum](https://github.com/Guard-Core/axum-guard-rs), [actix-web](https://github.com/Guard-Core/actix-guard-rs) (this repo), and [rocket](https://github.com/Guard-Core/rocket-guard-rs)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Usage

```rust
use actix_guard_rs::{default_config, GuardTransform};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .route("/", actix_web::web::to(|| async { "ok" }))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Engine surfaces (public config)

Every stateful decision and emission runs through the engine facade's rate-limit stage, configured through `GuardTransform` builders:

| Surface | Builder / idiom |
|---|---|
| Rate-limit tiers | `.with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`; a `RouteRateLimits` request extension wins), `.with_geo_handler(handler)` (geo tiers) |
| Detection exclusions | `.with_detection_exclusions(config)` (global `excluded_detection_headers/params/body_fields`, `enabled_detection_categories`, `detection_scan_body`); per route via a `RouteDetectionExclusions` request extension (a non-`None` route value replaces the global set; headers always merge) |
| Events + log settings | `.with_event_bus(bus)` (`SecurityEventBus` hook registration), `.with_observability(config)` (`log_suspicious_level`, `muted_check_logs`, the `log_sensitive_headers/params/body_fields` redaction sets) |
| `on_block` + custom errors | `.with_on_block(hook)`, `.with_custom_error_responses(map)` (status-to-body overrides on every block answer, including the `400` detection block) |
| Distributed mode | `.with_distributed_store(window_store, prefix, fail_open)` + `.with_distributed_ban_store(ban_store)` (fail-closed backend errors answer `503 Redis rate limiting unavailable`) |
| Passive mode | `.with_passive_mode(true)` (windows and counters still record, log lines and events still fire, no `400`/`403`/`429` renders, auto-ban feeds suppressed) |

Scan notes: the query string is scanned as `parse_qsl`-decoded per-parameter pairs (what makes `excluded_detection_params` functional), and excluded headers scan with their known false-positive categories suppressed (`ssrf` for address-chain values) instead of a blanket skip.

## Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| The distributed backend fails with `redis_fail_open = false` | `503 Service Unavailable` | `Redis rate limiting unavailable` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The bodies follow the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`, same as the Python family), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough.

Engine panics are caught with `catch_unwind` on the worker thread, so a detected panic still produces a response instead of unwinding out of the request future. `panic = "abort"` in the release profile disables that recovery.

## Rate limiting and IP banning

Two opt-in builder methods install the engine's stateful stage, mirroring the reference pipeline's order (ban check first, then the limiter, both before body buffering and detection):

```rust
use actix_guard_rs::{GuardTransform, IpBanConfig, IpBanManager, RateLimitConfig, RateLimiter, ThreatBanEntry};

let limiter = RateLimiter::new(RateLimitConfig {
    enable_rate_limiting: true,
    rate_limit: 30,
    rate_limit_window: 10,
    ..RateLimitConfig::default()
})
.expect("valid config");

let manager = IpBanManager::new();
let bans = IpBanConfig::new(
    true,
    10,
    3600,
    [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
)
.expect("valid config");

let transform = actix_guard_rs::GuardTransform::new(actix_guard_rs::default_config())
    .with_rate_limiting(limiter)
    .with_ip_banning(manager, bans);
```

- A rate-limit crossing answers `429 Too Many Requests` with `Retry-After: <window seconds>`. With the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation toward the auto-ban engine; the response stays `429` and the ban bites on the next request (`403 IP address banned`).
- A live ban on the client IP answers `403 Forbidden` (`IP address banned`) before the limiter, so banned traffic never consumes rate budget.
- Every detected threat counts its categories per client IP; a crossed `threat_ban_config` entry (or the flat `auto_ban_threshold`) bans on the spot, answering `403 Forbidden` (`IP has been banned`). `config.enable_ip_banning = false` counts violations but never bans.
- Both stages honor the `exempt_ips` contract: whitelisted and exempt IPs are never rate limited, never banned, and never counted; unattributed requests (no peer address) skip the stage but are still detection-screened.
- The limiter, ban store, and violation counters are shared across all workers through an `Arc`, and the engine handles are cheaply clonable, so out-of-band handles (admin unban endpoints, stats) work alongside the installed transform.

## Body cap

Request bodies are buffered so the engine can inspect them, and the buffer is bounded. The cap defaults to the engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the ecosystem default) and is configurable:

```rust
let transform = actix_guard_rs::GuardTransform::with_defaults()
    .with_body_cap(1_048_576);
```

A body larger than the cap is rejected with `413` rather than forwarded unscanned: the engine would only ever see a truncated prefix, which would be a bypass vector.

## Request rebuilding

actix Web consumes a request's payload as it is read, so the middleware buffers the body and hands the next service a rebuilt `ServiceRequest` (`into_parts`, buffer under the cap, `from_parts` around the buffered bytes). The wrapped service observes the request exactly as the client sent it, body included. The next service is shared through an `Rc`: actix Web builds its service tree per worker on single-threaded event loops, so this is free and never crosses threads.

## WebSocket guard (upgrades)

`websocket::WebSocketGuard` is a `Transform` for the upgrade path, ported from fastapi-guard's `guard/websocket.py`: an upgrade request (`Upgrade: websocket` + an `upgrade` token in `Connection`) runs the reference check sequence before the handshake completes, and a blocked handshake is rejected with `403 Forbidden` pre-accept, carrying the close shape on `X-Guard-WebSocket-Close` / `X-Guard-WebSocket-Close-Reason` (net/http has no pre-accept close frame; this is the HTTP-level translation of Starlette's `WebSocketException` denial). The close codes are the reference's: `1008 Policy Violation` for every policy denial (IP banned, IP not allowed, rate limit exceeded, unknown client address under fail-secure, suspicious activity) and `1013 Try Again Later` for an engine malfunction (a panic in the check sequence, contained). The sequence: fail-secure unknown address, the ban arm, the `is_ip_allowed` gate + country arms (a whitelist match skips countries), the `ws` rate limit (skipped for whitelisted IPs), then the path/query/header penetration scan - an upgrade carries no body. Non-upgrade requests pass through untouched (the HTTP `GuardTransform` domain). Build it from the handles the app already holds with `WebSocketGuardConfig::new(default_config())` + the `with_ip_gate` / `with_ip_banning` / `with_rate_limiting` / `with_country_rules` / `with_fail_secure` builders.

## Status route

`status::GuardStatus` is the `add_status_route` mirror (fastapi-guard `guard/status.py` + `HandlerInitializer.get_initialization_status`): `App::service(GuardStatus::new().with_cloud_table(table).with_geo_configured(true))` mounts `GET /_guard/status` (`status::DEFAULT_STATUS_PATH`), serving the cloud-provider status table (`{"ready":..., "last_refreshed":<unix-seconds|null>, "entries":N}` per provider from the live `CloudIpTable`) and the geo-ip component (`null` without a handler, `{"configured":true}` with the lookup trait only, the `{ready, last_refreshed, entries}` health snapshot with the `IpInfoManager` lifecycle manager). The maintenance trio lives on `GuardTransform`: `reset()` drops the rate-limit windows, `refresh_cloud_ip_ranges()` schedules one single-flight refresh through `with_cloud_refresh_scheduler`, and `agent_stats()` answers the reference property's no-agent shape.

## Engine dependency

The Cargo.toml floors `guard-core-engine` and `guard-core-rs` at 4.3.2 and carries paths pointing at the engine and facade crates inside a sibling `guard-core-rs` checkout so local builds and CI compile them from source. CI checks out `Guard-Core/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `tower-guard-rs`.

Both halves of the sibling checkout are used: `guard-core-engine` for the detection entry point and the engine-side stages, and the `guard-core-rs` facade for the stage layers (the `guard_core_rs::*` stage types the transform installs).

## Stage surface (the reference 17-check pipeline, wired)

Every reference check the engine ships is installable on `GuardTransform`, and `GuardService` runs the installed set in the reference pipeline order: emergency mode, HTTPS enforcement, request logging, request size/content caps, required headers + authentication, referrer, custom validators, time windows, geo country blocking, cloud-provider blocking, user-agent filtering, bans, rate limiting, the custom-request check, and the response-side pass (behavioral return rules + security headers + CORS). The builder table lives in the crate docs.

## Not wired on purpose

- **WebSocket guard**: the middleware screens a WebSocket upgrade handshake like any request; frames after the upgrade are not intercepted. There is no per-frame guard surface.
- **Status route**: no `add_status_route` equivalent ships (a gap tracked family-wide); expose engine state through your own route if you need it.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires a sibling `guard-core-rs` checkout at `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out `guard-core-rs` first so the path dependency resolves.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
