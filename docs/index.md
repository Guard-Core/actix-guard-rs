# actix-guard-rs

`actix-guard-rs` is application-layer security middleware for
[actix-web](https://github.com/actix/actix-web) 4, powered by the
[guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine.
It is part of the [Guard ecosystem](https://github.com/Guard-Core).

The crate holds framework glue only: every detection decision comes from the
engine. `GuardTransform` is a working actix-web `Transform` factory and
`GuardService` a working `Service` over `ServiceRequest`. Requests are
screened before they reach your handlers, and the adapter is fail-secure: any
failure to complete the security check answers `500`, never an uninspected
passthrough.

## Ecosystem position

```text
guard-core (Python)           <- Reference implementation, spec owner
├── guard-core-rs             <- Rust engine: detection, preprocessing, semantics
│   ├── tower-guard-rs        <- Adapter: tower middleware
│   ├── axum-guard-rs         <- Adapter: axum layer over tower-guard-rs
│   ├── actix-guard-rs        <- Adapter: actix-web middleware (this repo)
│   └── rocket-guard-rs       <- Adapter: rocket fairing and guards
├── guard-core-go             <- Go port
└── guard-core-ts             <- TypeScript port
```

The adapter translates native request content into engine inputs (path, query
string, header values, buffered body), runs one engine call per request view,
and translates a threat verdict into a native block response.

## Installation

```bash
cargo add actix-guard-rs
```

The published crate is `1.0.0` and depends on the published
`guard-core-engine` `4.0.4`. Requires Rust 1.92 or later (edition 2024) and
actix-web 4. See [Installation](installation.md) for details.

## Quick start

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

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling
adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's
`detect(content, context, config)` takes content plus a context, and the
reference adapters do not scan the method either.

## Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

## Where to go next

- [Installation](installation.md) for requirements and dependency setup
- [API](api.md) for the full public surface and behavior tables
- [Examples](examples.md) for runnable applications
