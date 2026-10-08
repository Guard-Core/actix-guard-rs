# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

actix-guard-rs is the actix-web adapter for the Guard ecosystem: an [`actix_web::dev::Transform`](https://docs.rs/actix-web/latest/actix_web/dev/trait.Transform.html) plus [`actix_web::dev::Service`](https://docs.rs/actix-web/latest/actix_web/dev/trait.Service.html) that screens `ServiceRequest` traffic through the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine before forwarding it to the wrapped service. It contains no security logic of its own.

- **Repository**: https://github.com/Guard-Core/actix-guard-rs
- **Language**: Rust, edition 2024, MSRV 1.92
- **License**: MIT OR Apache-2.0
- **Version**: 1.2.0 (published to crates.io)
- **Status**: implemented, tested, and published. The engine is a path dependency into a sibling `guard-core-rs` checkout; note the crates.io yank below (see [Engine Dependency](#engine-dependency)).

## Ecosystem Position

```
guard-core (Python)              <- Reference implementation, spec owner
└── guard-core-rs (Rust engine)  <- guard-core-engine: detect, preprocessor, semantic, compiler
    ├── tower-guard-rs           <- tower Layer + Service (axum-guard-rs composes it)
    ├── actix-guard-rs (this)    <- actix-web Transform + Service
    └── rocket-guard-rs          <- Rocket Fairing + request guards (v1.1.0)
```

Downstream consumers register `GuardTransform` with `App::wrap` (or wrap any `Service<ServiceRequest>` tree with it directly).

## Boundary Rules

- **No security logic in this crate.** Detection comes from `guard-core-engine`'s `detect`. Policy values (thresholds, caps) are configuration, not logic.
- **No other framework dependencies.** This crate depends on `actix-web`, `bytes`, `futures-core`, and the engine. Never add `axum`, `hyper`, `tower`, `rocket`, or a tokio runtime dependency to `[dependencies]`.
- **No modifications to the engine.** Engine behavior changes are `guard-core-rs` PRs.
- **Fail-secure, always.** A body read error, an engine panic, or a body over the cap must never result in an uninspected passthrough. Failures answer `500` (or `413` for oversize).

## Engine Integration

`guard-core-engine` exposes exactly one detection entry point, which this adapter calls once per request view:

```rust
pub fn detect(content: &str, request_context: &str, config: &DetectConfig) -> DetectVerdict
```

`DetectConfig` has five public fields and **no `Default` impl**; the ecosystem defaults are pinned in `crate::default_config()` (10 000 / 262 144 / true / 0.7 / 1.0), matching the conformance corpus knobs. `DetectVerdict` carries `is_threat`, `threat_score`, `threats`, `original_length`, `processed_length` and **no response shape at all**: the `400`/`403`/`413`/`429`/`500` translation lives in this adapter (`src/response.rs`) and follows the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`).

View mapping (documented in `src/lib.rs` and `src/service.rs::scan_views`):

| Request part | Context | Evaluated |
|---|---|---|
| `request.path()` | `url_path` | when not `/` |
| `request.query_string()` | `query_param` | when non-empty |
| header values | `header` | when the name is not excluded |
| buffered body | `request_body` | when non-empty after lossy UTF-8 decode |

The method is not scanned: `detect` has no method parameter. Non-UTF-8 header values are skipped (they cannot be represented as `&str`).

## Request Rebuilding and Service Sharing (actix specifics)

actix Web consumes a request's payload while it is read, so the middleware buffers it and rebuilds the request before forwarding. The pattern (see "Request rebuilding" in `src/lib.rs`):

1. `ServiceRequest::into_parts()` into `HttpRequest` + `Payload`.
2. Poll the payload to completion under the body cap (`Payload` is `Unpin` + `Stream`; a `std::future::poll_fn` loop, no futures-util).
3. `ServiceRequest::from_parts` around `Payload::from(buffered_bytes)`.

There is no `extract_replacement_body` helper in actix-web 4.x; this is the same split/rebuild shape the framework's own body-consuming paths use.

The next service is shared through an `Rc<S>` (`GuardService`), not cloned: the scanning future must own the inner service because the inner call happens only after buffering completes, and the services actix Web hands to a middleware (e.g. `AppRouting`-derived trees) are not `Clone`. actix Web builds its service tree per worker on single-threaded event loops, so the `Rc` is free and never crosses threads. Consequences: the guard's `Future` is not `Send` (fine for actix), and `GuardTransform` cannot be shared across workers after `new_transform` (the transform factory itself is `Clone + Send + Sync`-friendly plain data).

## Engine Dependency

- `Cargo.toml` pins `guard-core-engine` and `guard-core-rs` at 4.2.0 with paths into the sibling checkout (`../guard-core-rs/crates/guard-core-engine`, `../guard-core-rs/crates/guard-core-rs`).
- Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake); the 1.2.0 release trains with the 4.2.0 engine and restores registry resolution.
- **TODO(engine):** switch to the versioned crates.io dependency once `guard-core-rs` is tagged and published.
- The engine crate is used directly for `detect`; the facade dependency supplies the pipeline-side modules (events, geo, cloud provider, responses, and the rate-limit/ban stage wiring). The facade re-exports the full engine stage set since 4.1.0.
- CI checks out `Guard-Core/guard-core-rs` (branch `master`, moving branch by design, documented in `.github/workflows/ci.yml`) into `../guard-core-rs` before building, mirroring `tower-guard-rs`. Do not replace that with a git dependency without updating the CI comment and this file.

## Development Commands

CI is the source of truth (`.github/workflows/ci.yml`); there is no Makefile.

```bash
cargo check --all-targets                              # type check
cargo fmt --all -- --check                             # format gate
cargo clippy --all-targets -- -D warnings              # lint gate (pedantic is warn, so -D warnings enforces it)
cargo test                                             # unit + integration + doctests (workspace: adapter + examples)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps         # rustdoc gate
cargo deny check                                       # advisories, licenses, bans, sources (deny.toml)
```

A sibling `guard-core-rs` checkout at `../guard-core-rs` is required for every command.

The example apps under `examples/` build and run like any workspace member:

```bash
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait    # live smoke stack
SMOKE_PORT=8091 docker compose -f examples/simple_app/docker-compose.yml up ...   # remapped host port
```

The compose stacks also need the sibling `../guard-core-rs` checkout: the
Dockerfile receives the engine source through a compose
`additional_contexts` entry named `engine` pointing at `../../../guard-core-rs`
(relative to the compose file). The `live-smoke` workflow runs the simple_app
stack and the full curl assertion matrix on every push/PR; `upstream-drift`
runs the suite daily against a fresh `guard-core-rs@master` checkout placed at
the path dependency location. `security.yml` runs `cargo deny check` on
push/PR and weekly. `release.yml` gates `v*` tag pushes with the full suite
plus a tag/version consistency check; crates.io publishing is manual and
owner-gated.

## Project Structure

```
actix-guard-rs/
├── Cargo.toml / Cargo.lock          # adapter package + workspace (examples are members)
├── deny.toml                        # cargo-deny: advisories, licenses, bans, sources
├── src/
│   ├── lib.rs        # crate docs, GuardTransform, default_config, re-exports
│   ├── service.rs    # GuardService: buffering, view scanning, dispatch, EXCLUDED_HEADERS
│   └── response.rs   # 403/413/500 builders and their public message constants
├── tests/integration.rs  # actix-web test-utility behavior tests through the public API
├── examples/
│   ├── simple_app/       # minimal guarded App: main.rs, Dockerfile, compose, README
│   └── advanced_app/     # env-driven config, route-scoped guards: main.rs, Dockerfile, compose, README
└── .github/
    ├── workflows/ci.yml             # push/PR: fmt, clippy, test, doc, MSRV
    ├── workflows/security.yml       # push/PR + weekly: cargo deny check
    ├── workflows/live-smoke.yml     # push/PR: dockerized simple_app smoke with curl assertions
    ├── workflows/upstream-drift.yml # daily: suite against guard-core-rs@master
    ├── workflows/release.yml        # v* tag gate: matrix test + tag/version consistency
    └── workflows/issue-link.yml     # PRs must reference an open issue
```

## Testing

- `cargo test` runs 12 unit tests (`src/`), 12 integration tests (`tests/integration.rs`), and 4 doctests (3 run, 1 intentionally `ignore`d syntax sketch). All must pass.
- Coverage must include: benign passthrough (method/path/header/body preserved byte-for-byte through the rebuilt request), XSS in body, traversal in path, command injection in query (`$(echo id)`, percent-encoded as `$(echo%20id)` because raw spaces are invalid in a URI and the engine's preprocessor decodes it back), XSS in a scanned header, an excluded header not scanned, `413` over the cap, body passthrough under the cap (and exactly at it), inner service errors propagated unswallowed, engine panic to `500`, body read error to `500`, and 24 concurrent requests screened independently via `actix_web::rt::spawn`.
- The engine-panic test uses `GuardTransform::with_detect_fn`, a `#[cfg(test)]`-only seam. Do not expose a public detector-injection API; production must always call `guard_core_engine::detect::detect`.
- Payloads are chosen from the spec 4.1.0 conformance corpus so they are guaranteed threats, not guesses. New blocked-path tests should do the same (see `guard-core-rs/conformance/guard-core-spec-4.1.0/cases/`).

## Code Quality Standards

- `[lints]` in `Cargo.toml`: `unsafe_code = "forbid"`, `clippy::all = "deny"`, `clippy::pedantic = "warn"` (enforced as errors by CI's `-D warnings`). `clippy::nursery` is deliberately not enabled: its lints drift between clippy versions, as `guard-core-rs` found.
- No `#[allow(...)]` in `src/`. Test code prefers fixing the lint too.
- rustdoc warnings are errors in CI.

## Best Practices

1. **Keep the engine call surface unchanged.** Every request goes through `scan_request` -> `catch_unwind` -> `detect`. Do not bypass the panic recovery.
2. **Do not weaken fail-secure.** Any new failure path must map to `500` or a documented rejection, never to a passthrough.
3. **Keep `EXCLUDED_HEADERS` in sync with `tower-guard-rs` and `guard-core-ts`** when it changes, and record the reason in the const's doc comment.
4. **Run the full local gate before committing**: fmt, clippy, test, doc, cargo deny. CI runs all five.
5. **Example apps are part of the workspace.** `examples/simple_app` and `examples/advanced_app` build with a plain `cargo build` from the repo root; when you change the adapter's public API or response shapes, update the examples and their READMEs (and re-run the live smoke assertions) in the same change.
6. **Conventional commits** (`feat:`, `fix:`, `docs:`, `ci:`), matching history. No AI attribution in commit messages.
7. **Document status honestly.** Nothing here is published; say so in the README and crate docs rather than implying a crates.io release. crates.io publishing is manual and owner-gated; the release workflow only gates the tag.
8. **Update the README behavior tables** when the mapping, response shapes, or cap semantics change. The tables are the contract users read.
9. **Keep the engine surface claims honest.** The engine ships the detect pipeline plus the in-memory rate limiter, ban store, geo country rules, cloud provider checks, and distributed store traits (Redis backends are wired by the consumer, not bundled). Do not document capabilities the engine does not expose.

## Related Projects

- [guard-core-rs](https://github.com/Guard-Core/guard-core-rs): Rust detection engine (this crate's dependency).
- [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs): tower adapter whose semantics this crate mirrors.
- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation and spec owner.
- [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): the most mature adapter in the ecosystem, a useful reference for feature coverage.
