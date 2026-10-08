---
name: actix-guard-rs
description: Use when working in actix-guard-rs (github.com/Guard-Core/actix-guard-rs), the actix-web 4 adapter for the guard-core-rs detection engine: editing the Transform/Service middleware, adding or changing engine view mapping (url_path/query_param/header/request_body), changing the request body buffering cap or the 403/413/500 fail-secure response translation, changing the request-rebuild or Rc service-sharing design, wiring the guard-core-rs engine dependency (path vs versioned, CI checkout), or answering questions about what the adapter inspects and blocks. Covers CI-verified cargo commands, the EXCLUDED_HEADERS policy, and the cfg(test) detector seam for panic-recovery tests.
---

# actix-guard-rs

actix-web 4 adapter for the Guard ecosystem. `GuardTransform` + `GuardService` screen `ServiceRequest` traffic through the `guard-core-engine` detection engine and short-circuit with a `403`/`413`/`500` when needed. No security logic lives here.

## Quick Reference

```bash
# A sibling guard-core-rs checkout at ../guard-core-rs is required.
cargo check --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings   # pedantic is warn, so this enforces it
cargo test                                  # 12 unit + 12 integration + 3 doctests (1 ignored)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Public API

- `GuardTransform::new(DetectConfig)`, `GuardTransform::with_defaults()`, `GuardTransform::with_body_cap(usize)`. Implements `actix_web::dev::Transform<S, ServiceRequest>` -> `GuardService<S>`. Register with `App::wrap`.
- `GuardService<S>` implements `Service<ServiceRequest>` with `Response = ServiceResponse` (type-erased `BoxBody`) and `Error = actix_web::Error`. Bounds: `S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static`, `S::Future: 'static`, `B: MessageBody + 'static`.
- `default_config() -> DetectConfig` pins the ecosystem defaults because the engine's `DetectConfig` has no `Default`: `max_content_length` 10 000, `max_full_scan_bytes` 262 144, `preserve_attack_patterns` true, `semantic_threshold` 0.7, `threat_score_threshold` 1.0.
- `BLOCKED_MESSAGE` / `OVERSIZE_MESSAGE` / `FAILURE_MESSAGE` are the public detail strings.

## Engine Mapping

`guard_core_engine::detect::detect(content, request_context, config) -> DetectVerdict` is called once per view:

| Request part | Context |
|---|---|
| `request.path()` (not `/`) | `url_path` |
| `request.query_string()` (non-empty) | `query_param` |
| header value (name not excluded) | `header` |
| buffered body (non-empty after lossy UTF-8) | `request_body` |

`DetectVerdict` carries `is_threat`/`threat_score`/`threats` and no response shape; the response translation is adapter-side in `src/response.rs`.

## Behavior Contracts

- Block: `400` + `Suspicious activity detected`.
- Oversize body: `413` + `Payload too large`. Cap defaults to `max_full_scan_bytes`; oversize is rejected, never passed unscanned.
- Body read error or engine panic: `500` + `Security check failed`. Fail-secure, unlike the TypeScript adapters which fail open.
- `EXCLUDED_HEADERS` (never scanned): `host`, `user-agent`, `accept`, `accept-encoding`, `connection`, `origin`, `referer`, plus every `sec-*` header. Mirrors `guard-core-ts` and `tower-guard-rs`.
- Method is not scanned (the engine has no method parameter). Non-UTF-8 header values are skipped.
- Requests are rebuilt before forwarding: `into_parts`, buffer the `Payload` under the cap via a `poll_fn` loop, then `ServiceRequest::from_parts` around `Payload::from(buffered_bytes)`. The inner service sees the original request bytes.
- The next service is shared through `Rc<S>` (actix's `AppRouting`-tree services are not `Clone`, and the inner call must happen after buffering). The guard's future is deliberately not `Send`; actix workers are single-threaded.

## Footguns

- `panic = "abort"` disables the `catch_unwind` recovery; the process dies before the `500` can be returned. Documented, not mitigated.
- The panic test relies on `#[cfg(test)] GuardTransform::with_detect_fn`. It does not exist in production builds; do not make it public.
- `App::wrap` applies the transform over `T::Service`; do not add an `S: Clone` bound back, it breaks `App::wrap` (actix app services are not `Clone`).
- The engine dependency is a path dependency (`../guard-core-rs/crates/guard-core-engine`) with a `TODO(engine)` to move to the versioned crate. CI checks out `Guard-Core/guard-core-rs@master` into place. The facade crate `guard-core-rs` is NOT used because it does not re-export `detect`.
- Payloads in tests must come from the spec 4.0.2 corpus (`guard-core-rs/conformance/guard-core-spec-4.0.2/cases/`) so they are guaranteed threats. Raw spaces are invalid in test URIs: percent-encode (`$(echo id)` becomes `$(echo%20id)`); the engine's preprocessor decodes it back.

## Related

- `tower-guard-rs`: sibling adapter whose semantics this crate mirrors; `axum-guard-rs` composes it.
- `guard-core-rs`: the engine. Engine behavior changes belong there, not here.
