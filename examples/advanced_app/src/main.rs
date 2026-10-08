//! Production-shaped guarded actix-web application.
//!
//! Differences from `simple_app`:
//!
//! - The engine [`DetectConfig`] and the adapter body cap are driven by
//!   environment variables (see `env_config` below), so a deployment tunes
//!   detection without a rebuild.
//! - Route-scoped guard configuration: the `/admin` scope is screened by a
//!   second, stricter `GuardTransform` (threat-score threshold halved by
//!   default), while general routes use the default-derived configuration.
//!   Actix scope-level `wrap` is the route scoping mechanism; the adapter
//!   surface has no route IDs.
//! - `GET /health` is registered on the `App` in front of both scopes,
//!   mirroring excluded-path behavior.
//!
//! The guard-core-rs engine currently ships the CPU-bound detection pipeline
//! only: there is no rate limiter, ban manager, or Redis surface to drive, so
//! this example scopes guard configuration per scope and stops there.

use actix_guard_rs::{DetectConfig, GuardTransform, default_config};
use actix_web::{App, HttpResponse, HttpServer, web};

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn root() -> HttpResponse {
    HttpResponse::Ok().body("actix-guard-rs advanced app")
}

async fn search() -> HttpResponse {
    HttpResponse::Ok().body("search ok")
}

async fn echo(body: web::Bytes) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

async fn stats() -> HttpResponse {
    HttpResponse::Ok().body("stats")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("APP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let config = env_config();
    let body_cap = env_usize("GUARD_BODY_CAP", config.max_full_scan_bytes);
    // The admin scope screens with a stricter threshold: every env override
    // applies, but the score threshold is lowered relative to the general
    // config so borderline payloads are caught on admin surface only.
    let mut admin_config = config;
    admin_config.threat_score_threshold = env_f64(
        "GUARD_ADMIN_THREAT_SCORE_THRESHOLD",
        (config.threat_score_threshold * 0.5).min(1.0),
    );

    let bind_addr = addr.clone();
    HttpServer::new(move || {
        // The /admin scope is registered before the empty-prefix scope: an
        // actix scope owns its prefix, so anything under /admin must reach
        // the admin scope before the catch-all general scope claims it.
        App::new()
            .route("/health", web::get().to(health))
            .service(
                web::scope("/admin")
                    .wrap(GuardTransform::new(admin_config).with_body_cap(body_cap))
                    .route("/stats", web::get().to(stats)),
            )
            .service(
                web::scope("")
                    .wrap(GuardTransform::new(config).with_body_cap(body_cap))
                    .route("/", web::get().to(root))
                    .route("/search", web::get().to(search))
                    .route("/echo", web::post().to(echo)),
            )
    })
    .bind(bind_addr)?
    .run()
    .await
}

/// Build the engine [`DetectConfig`] from environment variables.
///
/// Every knob is optional; unset variables fall back to the ecosystem
/// defaults pinned in [`default_config`].
///
/// | Variable | Field | Default |
/// |---|---|---|
/// | `GUARD_MAX_CONTENT_LENGTH` | `max_content_length` | `10000` |
/// | `GUARD_MAX_FULL_SCAN_BYTES` | `max_full_scan_bytes` | `262144` |
/// | `GUARD_PRESERVE_ATTACK_PATTERNS` | `preserve_attack_patterns` | `true` |
/// | `GUARD_SEMANTIC_THRESHOLD` | `semantic_threshold` | `0.7` |
/// | `GUARD_THREAT_SCORE_THRESHOLD` | `threat_score_threshold` | `1.0` |
/// | `GUARD_BINARY_MIN_RUN_LENGTH` | `binary_min_run_length` | `16` |
/// | `GUARD_MAX_SCAN_VALUES` | `max_scan_values` | `512` |
/// | `GUARD_MAX_SCAN_CHARS` | `max_scan_chars` | `65536` |
/// | `GUARD_MAX_JSON_DEPTH` | `max_json_depth` | `32` |
fn env_config() -> DetectConfig {
    let defaults = default_config();
    DetectConfig {
        max_content_length: env_usize("GUARD_MAX_CONTENT_LENGTH", defaults.max_content_length),
        max_full_scan_bytes: env_usize("GUARD_MAX_FULL_SCAN_BYTES", defaults.max_full_scan_bytes),
        preserve_attack_patterns: env_bool(
            "GUARD_PRESERVE_ATTACK_PATTERNS",
            defaults.preserve_attack_patterns,
        ),
        semantic_threshold: env_f64("GUARD_SEMANTIC_THRESHOLD", defaults.semantic_threshold),
        threat_score_threshold: env_f64(
            "GUARD_THREAT_SCORE_THRESHOLD",
            defaults.threat_score_threshold,
        ),
        binary_min_run_length: env_usize(
            "GUARD_BINARY_MIN_RUN_LENGTH",
            defaults.binary_min_run_length,
        ),
        max_scan_values: env_usize("GUARD_MAX_SCAN_VALUES", defaults.max_scan_values),
        max_scan_chars: env_usize("GUARD_MAX_SCAN_CHARS", defaults.max_scan_chars),
        max_json_depth: env_usize("GUARD_MAX_JSON_DEPTH", defaults.max_json_depth),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}
