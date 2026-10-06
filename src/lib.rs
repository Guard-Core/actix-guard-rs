//! # actix-guard-rs
//!
//! Application-layer security middleware for
//! [Actix Web](https://github.com/actix/actix-web) 4, powered by the
//! [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection
//! engine. Part of the [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardTransform`] is a working [`Transform`]
//! factory and [`GuardService`] a working [`Service`] over `ServiceRequest`.
//! The engine is
//! wired in through `guard-core-engine` (a path dependency until the engine
//! is tagged and published). Per the ecosystem boundary rules, this adapter
//! holds framework glue only: every detection decision comes from the engine.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling adapters (`tower-guard-rs`, `guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS` in `src/service.rs`) |
//! | Body | `request_body` | Buffered first, capped (see below) |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body cap
//!
//! Request bodies are buffered so the engine can inspect them, and the
//! buffer is bounded by [`GuardTransform::with_body_cap`]. It defaults to the
//! engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262,144 bytes
//! in the ecosystem default). A request whose body exceeds the cap is
//! rejected with `413 Payload Too Large` rather than forwarded unscanned: the
//! engine would only ever see a truncated prefix, which would be a bypass
//! vector.
//!
//! ## Request rebuilding
//!
//! actix Web consumes a request's payload as it is read, so a body-inspecting
//! middleware must hand the next service a rebuilt request. The canonical
//! pattern used here:
//!
//! 1. Split the `ServiceRequest` with
//!    [`ServiceRequest::into_parts`](actix_web::dev::ServiceRequest::into_parts)
//!    into an `HttpRequest` and its `Payload`.
//! 2. Poll the payload to completion under the cap (`Payload` is `Unpin` and
//!    implements `Stream`, so a `poll_fn` loop buffers it without extra
//!    stream-utility dependencies).
//! 3. Rebuild with
//!    [`ServiceRequest::from_parts`](actix_web::dev::ServiceRequest::from_parts)
//!    around a fresh `Payload` built from the buffered bytes (actix Web's
//!    `HttpMessage::set_payload` would land in the same place, but the owning
//!    split/rebuild keeps the buffering future self-contained).
//!
//! The inner service therefore observes the request exactly as the client
//! sent it, body included.
//!
//! ## Engine surfaces (the 4.2.0 wave, all publicly configurable)
//!
//! Every stateful decision and emission goes through the engine facade's
//! rate-limit stage (`guard_core_rs::tower::RateLimitStage`); the
//! transform's builders are the public configuration:
//!
//! | Surface | Builder / idiom |
//! |---|---|
//! | Rate-limit tiers | [`GuardTransform::with_route_tiers`] (`path -> Option<RouteRateLimits>`, a [`RouteRateLimits`] request extension wins), [`GuardTransform::with_geo_handler`] (geo tiers) |
//! | Detection exclusions | [`GuardTransform::with_detection_exclusions`] (global), a [`RouteDetectionExclusions`] request extension (per route) |
//! | Events + log settings | [`GuardTransform::with_event_bus`], [`GuardTransform::with_observability`] (`log_suspicious_level`, `muted_check_logs`, the `log_sensitive_*` redaction sets) |
//! | `on_block` + custom errors | [`GuardTransform::with_on_block`], [`GuardTransform::with_custom_error_responses`] |
//! | Distributed mode | [`GuardTransform::with_distributed_store`] + [`GuardTransform::with_distributed_ban_store`] |
//! | Passive mode | [`GuardTransform::with_passive_mode`] (log-only: windows and counters record, no block renders, auto-ban feeds suppressed) |
//!
//! Scan semantics note: the query string is now scanned as `parse_qsl`-
//! decoded per-parameter pairs (the reference reads decoded values), which
//! is what makes `excluded_detection_params` functional, and the header
//! set the resolution marks as excluded scans with its known
//! false-positive categories suppressed (`ssrf` for address-chain values)
//! instead of a blanket skip.
//!
//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
//! | The ban stage finds a live ban on the client IP | `403 Forbidden` | `IP address banned` |
//! | The rate limiter records a crossing of `rate_limit` | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
//! | Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
//! | Engine flags a view and the crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! The IP gate is optional (`GuardTransform::with_ip_gate`); when it is
//! configured, `exempt_ips` (like a whitelist match) only sets the skip state
//! on the request, never a deny path of its own - the exempt-vs-whitelist
//! contract in the engine's `ip_gate` module. The stateful stages honor that
//! contract: the rate limiter (`GuardTransform::with_rate_limiting`) and the
//! ban/auto-ban stage (`GuardTransform::with_ip_banning`) skip whitelisted and
//! exempt IPs for exactly what the reference skips (rate limiting, violation
//! counting, banning) and never skip detection, which always scans every
//! request, exempt or not. A user-agent filter and cloud-provider blocking
//! do not exist yet.
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family) but
//! the adapter is deliberately **fail-secure**, unlike the TypeScript
//! adapters whose check pipeline logs and skips on error: any failure to
//! complete the security check results in `500`, never in an uninspected
//! passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`] on the worker thread,
//! so the default panic hook still prints. `panic = "abort"` in the release
//! profile disables that recovery, because the process dies before the guard
//! can respond.
//!
//! ## Example
//!
//! ```
//! use actix_guard_rs::{default_config, GuardTransform};
//! use actix_web::{test, web, App, HttpResponse};
//!
//! # let runtime = actix_web::rt::System::new();
//! # runtime.block_on(async {
//! let service = test::init_service(
//!     App::new()
//!         .wrap(GuardTransform::new(default_config()))
//!         .route("/", web::post().to(|| async { HttpResponse::Ok().finish() })),
//! )
//! .await;
//!
//! // Benign traffic passes through untouched.
//! let request = test::TestRequest::post()
//!     .uri("/")
//!     .set_payload("benign body")
//!     .to_request();
//! let response = test::call_service(&service, request).await;
//! assert_eq!(response.status(), actix_web::http::StatusCode::OK);
//!
//! // Attack traffic is blocked by the engine.
//! let request = test::TestRequest::get()
//!     .uri("/files/../../etc/passwd")
//!     .to_request();
//! let response = test::call_service(&service, request).await;
//! assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
//! # });
//! ```

mod response;
mod service;

pub mod status;
pub mod websocket;

use actix_web::Error;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};
pub use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RouteDetectionExclusions,
};
pub use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
pub use guard_core_engine::geo::GeoIpHandler;
pub use guard_core_engine::ip_ban::{
    BanError, BanRecord, Clock, IpBanConfig, IpBanConfigError, IpBanManager, ResolvedBan,
    ThreatBanEntry, ViolationCounters,
};
pub use guard_core_engine::ip_gate::{
    IpGateConfig, IpGateDecision, IpGateDenial, IpGateError, IpGateVerdict,
};
pub use guard_core_engine::rate_limit::{
    RateLimitConfig, RateLimitConfigError, RateLimitDecision, RateLimitEntry, RateLimitTier,
    RateLimiter, RouteRateLimits, TierDecision,
};
pub use guard_core_rs::events::SecurityEventBus;
pub use guard_core_rs::responses::{BlockPayload, CustomErrorResponses, OnBlockHook};
pub use guard_core_rs::tower::{ObservabilityConfig, RequestObservation, StageResponse};

pub use crate::response::{
    ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE,
    OVERSIZE_MESSAGE, RATE_LIMITED_MESSAGE,
};
pub use crate::service::GuardService;

use guard_core_rs::tower::{RateLimitStage, RateLimitStageConfig, RouteRateResolver};
use std::sync::Arc;

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
/// | `binary_min_run_length` | `16` |
///
/// # Example
///
/// ```
/// let config = actix_guard_rs::default_config();
/// let transform = actix_guard_rs::GuardTransform::new(config);
/// # let _ = transform;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

/// The stateful stage's ban half: the shared ban store, the shared violation
/// counters (one middleware instance = one store pair), and the config that
/// gates banning and threshold resolution. The pair is injected into the
/// engine stage (`RateLimitStageBuilder::ban_manager`), so out-of-band
/// handles stay authoritative.
pub(crate) struct BanState {
    manager: IpBanManager,
    counters: ViolationCounters,
    config: IpBanConfig,
}

impl core::fmt::Debug for BanState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BanState")
            .field("manager", &self.manager)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Screens actix Web requests with the Guard engine before they reach the
/// wrapped service.
///
/// Register it with [`App::wrap`](actix_web::App::wrap):
///
/// ```ignore
/// App::new().wrap(GuardTransform::new(default_config()))
/// ```
///
/// The compiled example in the crate docs shows the full setup.
///
/// The transform applies to every request routed after it. Wrapped services
/// are shared through an `Rc` (see [`GuardService`]); actix Web builds its
/// service tree per worker, so this is free and never crosses threads.
#[derive(Clone)]
pub struct GuardTransform {
    config: DetectConfig,
    body_cap: usize,
    ip_gate: Option<IpGateConfig>,
    rate_limiter: Option<Arc<RateLimiter>>,
    ban_state: Option<Arc<BanState>>,
    route_tiers: Option<RouteRateResolver>,
    geo_handler: Option<Arc<dyn GeoIpHandler>>,
    events: Option<Arc<SecurityEventBus>>,
    observability: Option<ObservabilityConfig>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    passive_mode: bool,
    distributed: Option<(Arc<dyn SlidingWindowStore>, String, bool)>,
    distributed_ban_store: Option<Arc<dyn BanStore>>,
    detection_exclusions: Option<DetectionExclusionConfig>,
    scan_fn: ScanFn,
    stage: Option<Arc<RateLimitStage>>,
}

impl GuardTransform {
    /// Build a transform from an engine [`DetectConfig`].
    ///
    /// The body buffering cap starts at `config.max_full_scan_bytes`, and no
    /// IP gate, rate limiter, or ban store is configured (each can be added
    /// with [`GuardTransform::with_ip_gate`],
    /// [`GuardTransform::with_rate_limiting`], and
    /// [`GuardTransform::with_ip_banning`]).
    #[must_use]
    pub fn new(config: DetectConfig) -> Self {
        Self {
            config,
            body_cap: config.max_full_scan_bytes,
            ip_gate: None,
            rate_limiter: None,
            ban_state: None,
            route_tiers: None,
            geo_handler: None,
            events: None,
            observability: None,
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            passive_mode: false,
            distributed: None,
            distributed_ban_store: None,
            detection_exclusions: None,
            scan_fn: guard_core_engine::detection_exclusions::scan_request,
            stage: None,
        }
    }

    /// Build a transform with [`default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(default_config())
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is rejected with `413 Payload Too Large`.
    /// A cap of `0` rejects every request that carries a non-empty body.
    ///
    /// # Example
    ///
    /// ```
    /// let transform = actix_guard_rs::GuardTransform::with_defaults()
    ///     // Reject bodies larger than 1 MiB with 413 instead of buffering more.
    ///     .with_body_cap(1_048_576);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.body_cap = body_cap;
        self
    }

    /// Install the global IP gate: a `whitelist`/`blacklist`/`exempt_ips`
    /// config built with [`IpGateConfig::new`] (which fails closed on an
    /// invalid entry).
    ///
    /// The gate runs before body buffering and before detection: an IP on the
    /// `blacklist` is denied with `403 Forbidden`, and so is any IP when a
    /// non-empty `whitelist` matches neither it nor an `exempt_ips` entry. A
    /// passed request gets the gate's [`IpGateDecision`] inserted into the
    /// request extensions, so downstream handlers can read the skip state
    /// (`is_whitelisted` / `is_exempt`). The client IP is the request's peer
    /// address; a request without one is not attributed and goes through
    /// detection unconditionally - detection still screens every request,
    /// exempt or not.
    ///
    /// # Example
    ///
    /// ```
    /// use actix_guard_rs::{GuardTransform, IpGateConfig};
    ///
    /// let gate = IpGateConfig::new(
    ///     [] as [&str; 0],
    ///     ["203.0.113.9"],
    ///     ["198.51.100.0/28"],
    /// )
    /// .expect("valid lists");
    /// let transform = GuardTransform::new(actix_guard_rs::default_config()).with_ip_gate(gate);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the rate limiter: an engine [`RateLimiter`] built over a
    /// [`RateLimitConfig`] (whose constructor fails closed on a zero limit or
    /// window). The limiter's own `enable_rate_limiting` switch decides
    /// whether it records and blocks, so attaching a disabled limiter is
    /// inert.
    ///
    /// The limiter stage runs after the IP gate and the ban stage and before
    /// body buffering and detection: a crossing is answered with
    /// `429 Too Many Requests` carrying `Retry-After: <window seconds>`,
    /// the references' rate-limit shape. When the limiter's
    /// `enable_rate_limit_auto_ban` is on and IP banning is configured
    /// ([`GuardTransform::with_ip_banning`]), every crossing counts one
    /// `rate_limit` violation toward the auto-ban engine. Both stages skip
    /// whitelisted and exempt IPs (the `exempt_ips` contract), and requests
    /// without a peer address cannot be attributed and are not rate
    /// limited - detection still screens them.
    ///
    /// The transform applies to every worker, and the workers share the one
    /// limiter through an `Arc`: the window store is process-global by
    /// design, exactly like the reference's middleware-scoped store.
    ///
    /// # Example
    ///
    /// ```
    /// use actix_guard_rs::{GuardTransform, RateLimitConfig, RateLimiter};
    ///
    /// let limiter = RateLimiter::new(RateLimitConfig {
    ///     enable_rate_limiting: true,
    ///     rate_limit: 30,
    ///     rate_limit_window: 10,
    ///     ..RateLimitConfig::default()
    /// })
    /// .expect("valid config");
    /// let transform =
    ///     GuardTransform::new(actix_guard_rs::default_config()).with_rate_limiting(limiter);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_rate_limiting(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Install the dynamic ban store and the auto-ban engine: an
    /// [`IpBanManager`] (optionally built with trusted proxies via
    /// `IpBanManager::with_trusted_proxies`) and an [`IpBanConfig`]
    /// (whose constructor fails closed on an invalid `threat_ban_config`).
    ///
    /// The ban stage runs after the IP gate and before body buffering and
    /// detection: a live ban on the client IP is answered with
    /// `403 Forbidden` (`IP address banned`), before rate limiting. The
    /// stage's violation counters feed the auto-ban engine exactly like the
    /// reference pipeline's suspicious-activity stage: every detected
    /// threat counts its categories per client IP (whitelisted IPs never
    /// count - the reference suspicious-activity stage skips a whitelisted
    /// IP only; exempt IPs DO count, which makes a crossed threshold ban
    /// even an exempt attacker), and a crossed
    /// `threat_ban_config` entry (or the flat `auto_ban_threshold`)
    /// bans on the spot, answering `403 Forbidden` (`IP has been banned`).
    /// The `config.enable_ip_banning` switch gates all of it; with it off
    /// the stage counts violations but never bans.
    ///
    /// Requests without a peer address cannot be attributed and are neither
    /// banned nor counted.
    ///
    /// The transform applies to every worker, and the workers share the one
    /// store pair through an `Arc`: bans and counts are process-global by
    /// design, exactly like the reference's middleware-scoped stores.
    ///
    /// # Example
    ///
    /// ```
    /// use actix_guard_rs::{GuardTransform, IpBanConfig, IpBanManager, ThreatBanEntry};
    ///
    /// let manager = IpBanManager::new();
    /// let config = IpBanConfig::new(
    ///     true,
    ///     10,
    ///     3600,
    ///     [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
    /// )
    /// .expect("valid config");
    /// let transform =
    ///     GuardTransform::new(actix_guard_rs::default_config()).with_ip_banning(manager, config);
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_ip_banning(mut self, manager: IpBanManager, config: IpBanConfig) -> Self {
        self.ban_state = Some(Arc::new(BanState {
            manager,
            counters: ViolationCounters::new(),
            config,
        }));
        self
    }

    /// Install the per-route rate-limit tier resolver:
    /// `path -> Option<RouteRateLimits>` (the tower counterpart of the
    /// reference's `request.state.route_config`). A
    /// [`RouteRateLimits`] request extension, when a stack provides one,
    /// wins over the resolver. The tier's `rate_limit`/`rate_limit_window`
    /// (and its per-country `geo_rate_limits`, resolved through
    /// [`GuardTransform::with_geo_handler`]) apply on top of the global tier;
    /// the first tier that crosses decides, answering the same
    /// `429 + Retry-After` shape.
    ///
    /// # Example
    ///
    /// ```
    /// use actix_guard_rs::{GuardTransform, RouteRateLimits, default_config};
    ///
    /// let transform =
    ///     GuardTransform::new(default_config()).with_route_tiers(std::sync::Arc::new(|path| {
    ///         if path.starts_with("/login") {
    ///             Some(RouteRateLimits::new(Some(5), None, None).expect("valid tiers"))
    ///         } else {
    ///             None
    ///         }
    ///     }));
    /// # let _ = transform;
    /// ```
    #[must_use]
    pub fn with_route_tiers(mut self, resolver: RouteRateResolver) -> Self {
        self.route_tiers = Some(resolver);
        self
    }

    /// Install the geolocation seam the geo rate-limit tier resolves
    /// through (`geo_handler.get_country(ip)`; the MMDB reading is the
    /// host's work, [`GeoIpHandler`] is the engine trait). Without a
    /// handler the geo tier never applies, exactly the reference's
    /// `if not geo_handler: return None`.
    #[must_use]
    pub fn with_geo_handler(mut self, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.geo_handler = Some(handler);
        self
    }

    /// Install the [`SecurityEventBus`] the stage's security events
    /// dispatch through (`penetration_attempt`, `rate_limited`,
    /// `ip_banned`, with the reference fields and metadata). Handlers
    /// receive every event and own the transport.
    #[must_use]
    pub fn with_event_bus(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Install the observability knobs ([`ObservabilityConfig`]): the
    /// `log_suspicious_level` (`None` composes no suspicious line), the
    /// `muted_check_logs` set, and the `log_sensitive_headers` /
    /// `log_sensitive_params` / `log_sensitive_body_fields` redaction sets
    /// (merged over the engine defaults) that the suspicious log lines,
    /// the event endpoint/user-agent fields, and the `on_block` payload
    /// redact through.
    #[must_use]
    pub fn with_observability(mut self, observability: ObservabilityConfig) -> Self {
        self.observability = Some(observability);
        self
    }

    /// Install the reference `on_block` callback: fired exactly once per
    /// blocked request (and once per passive-flagged detection, with
    /// `status_code = None`) with the reference [`BlockPayload`] keys
    /// (check name, reason, trigger, redacted path, method, status).
    /// Matching the engine stage's contract, the hook receives redacted
    /// payloads only when an [`ObservabilityConfig`] is installed.
    #[must_use]
    pub fn with_on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Install the reference `custom_error_responses` map: status code to
    /// message body, overriding the family default for that status on
    /// every block answer the guard renders (`429`, both `403` banned
    /// shapes, the `503` Redis-unavailable shape, and the `400`
    /// detection block).
    #[must_use]
    pub fn with_custom_error_responses(
        mut self,
        custom_error_responses: CustomErrorResponses,
    ) -> Self {
        self.custom_error_responses = custom_error_responses;
        self
    }

    /// Set the reference `passive_mode` (default `false`): log-only
    /// security. Sliding windows and violation counters still record, the
    /// log lines and events still fire, but no `400`/`403`/`429` is ever
    /// rendered and the auto-ban feeds are suppressed - the reference's
    /// passive paths.
    #[must_use]
    pub fn with_passive_mode(mut self, passive_mode: bool) -> Self {
        self.passive_mode = passive_mode;
        self
    }

    /// Run the limiter and ban engine over a distributed store (the
    /// reference `enable_redis && redis_handler` conjunction): a
    /// [`SlidingWindowStore`] plus the reference `redis_prefix` and
    /// `redis_fail_open` knobs. `redis_fail_open = false` (the default)
    /// answers the fail-closed `503 "Redis rate limiting unavailable"` on
    /// a backend error; `true` degrades to the in-memory window. Install
    /// a [`BanStore`] alongside with
    /// [`GuardTransform::with_distributed_ban_store`]. The traits are
    /// engine-side and client-free; `guard-core-rs`' `redis` feature
    /// ships a ready `RedisStore` backend.
    #[must_use]
    pub fn with_distributed_store(
        mut self,
        window_store: Arc<dyn SlidingWindowStore>,
        redis_prefix: &str,
        redis_fail_open: bool,
    ) -> Self {
        self.distributed = Some((window_store, redis_prefix.to_owned(), redis_fail_open));
        self
    }

    /// Attach the distributed ban store the ban engine shares (the
    /// reference `{prefix}banned_ips:{ip}` namespace). Only meaningful
    /// together with [`GuardTransform::with_distributed_store`].
    #[must_use]
    pub fn with_distributed_ban_store(mut self, ban_store: Arc<dyn BanStore>) -> Self {
        self.distributed_ban_store = Some(ban_store);
        self
    }

    /// Install the global detection-exclusion config
    /// ([`DetectionExclusionConfig`], the reference `SecurityConfig`
    /// fields of the same names): `excluded_detection_headers` (merged
    /// with the engine defaults), `excluded_detection_params`,
    /// `excluded_detection_body_fields`, `enabled_detection_categories`,
    /// and `detection_scan_body`. A
    /// [`RouteDetectionExclusions`] request extension (the per-route
    /// decorator surface) resolves on top of it per request: a non-`None`
    /// route value replaces the global set for that surface (the header
    /// set always merges).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: DetectionExclusionConfig,
    ) -> Self {
        self.detection_exclusions = Some(detection_exclusions);
        self
    }

    pub(crate) const fn config(&self) -> &DetectConfig {
        &self.config
    }

    pub(crate) const fn body_cap(&self) -> usize {
        self.body_cap
    }

    pub(crate) const fn ip_gate(&self) -> Option<&IpGateConfig> {
        self.ip_gate.as_ref()
    }

    pub(crate) const fn detection_exclusions(&self) -> Option<&DetectionExclusionConfig> {
        self.detection_exclusions.as_ref()
    }

    pub(crate) const fn observability(&self) -> Option<&ObservabilityConfig> {
        self.observability.as_ref()
    }

    pub(crate) const fn on_block(&self) -> Option<&OnBlockHook> {
        self.on_block.as_ref()
    }

    pub(crate) const fn custom_error_responses(&self) -> &CustomErrorResponses {
        &self.custom_error_responses
    }

    /// The installed engine stage (set by `Transform::new_transform`);
    /// every stateful decision and emission goes through it.
    pub(crate) fn stage(&self) -> Option<&RateLimitStage> {
        self.stage.as_deref()
    }

    /// Build the engine stage from the configured handles and seams.
    /// Every injected config is already validated (the `with_*` builders
    /// take pre-validated engine objects), so the stage build cannot
    /// fail; a panic here is a construction bug, not a runtime path.
    pub(crate) fn build_stage(&self) -> RateLimitStage {
        let rate_limit = self.rate_limiter.as_deref().map_or(
            RateLimitConfig {
                enable_rate_limiting: false,
                ..RateLimitConfig::default()
            },
            |limiter| limiter.config().clone(),
        );
        let ip_ban = self.ban_state.as_deref().map_or(
            IpBanConfig {
                enable_ip_banning: false,
                ..IpBanConfig::default()
            },
            |state| state.config.clone(),
        );
        let mut builder = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit,
            ip_ban,
            passive_mode: self.passive_mode,
            custom_error_responses: self.custom_error_responses.clone(),
        });
        if let Some(limiter) = &self.rate_limiter {
            builder = builder.limiter(limiter.as_ref().clone());
        }
        if let Some(state) = &self.ban_state {
            builder = builder.ban_manager(state.manager.clone(), state.counters.clone());
        }
        if let Some(resolver) = &self.route_tiers {
            {
                let resolver = Arc::clone(resolver);
                builder = builder.route_resolver(move |path| resolver(path));
            }
        }
        if let Some(handler) = &self.geo_handler {
            builder = builder.geo_handler(Arc::clone(handler));
        }
        if let Some(bus) = &self.events {
            builder = builder.events(Arc::clone(bus));
        }
        if let Some(observability) = &self.observability {
            builder = builder.observability(observability.clone());
        }
        if let Some(hook) = &self.on_block {
            builder = builder.on_block(Arc::clone(hook));
        }
        if let Some((store, prefix, fail_open)) = &self.distributed {
            builder = builder.distributed_store(Arc::clone(store), prefix, *fail_open);
        }
        if let Some(ban_store) = &self.distributed_ban_store {
            builder = builder.distributed_ban_store(Arc::clone(ban_store));
        }
        builder
            .build()
            .expect("guard configs are validated by their constructors")
    }

    #[cfg(test)]
    pub(crate) fn with_scan_fn(mut self, scan_fn: ScanFn) -> Self {
        self.scan_fn = scan_fn;
        self
    }

    pub(crate) const fn scan_fn(&self) -> ScanFn {
        self.scan_fn
    }
}

/// The multi-surface scan entry point stored in the layer.
///
/// Indirection exists so unit tests can substitute a panicking scan and
/// exercise the fail-secure path; production builds always store
/// [`guard_core_engine::detection_exclusions::scan_request`].
pub(crate) type ScanFn = fn(
    &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
    &guard_core_engine::detection_exclusions::ResolvedExclusions,
    &DetectConfig,
) -> guard_core_engine::detection_exclusions::RequestScanVerdict;

/// Manual [`core::fmt::Debug`]: the hook, resolver, and store seams are
/// trait objects without `Debug`, so the transform prints its configuration
/// shape and stops (`finish_non_exhaustive`).
impl core::fmt::Debug for GuardTransform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardTransform")
            .field("config", &self.config)
            .field("body_cap", &self.body_cap)
            .field("ip_gate", &self.ip_gate)
            .field("rate_limiter", &self.rate_limiter)
            .field("ban_state", &self.ban_state)
            .field("custom_error_responses", &self.custom_error_responses)
            .field("passive_mode", &self.passive_mode)
            .field("detection_exclusions", &self.detection_exclusions)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl<S, B> Transform<S, ServiceRequest> for GuardTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = GuardService<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let mut transform = self.clone();
        if transform.stage.is_none() {
            transform.stage = Some(Arc::new(self.build_stage()));
        }
        std::future::ready(Ok(GuardService::new(service, transform)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let transform = GuardTransform::new(default_config());
        assert_eq!(transform.body_cap(), 262_144);
        let transform = transform.with_body_cap(1024);
        assert_eq!(transform.body_cap(), 1024);
    }

    #[test]
    fn with_defaults_builds_the_corpus_config() {
        let transform = GuardTransform::with_defaults();
        assert_eq!(transform.body_cap(), 262_144);
        let config = *transform.config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn debug_prints_the_configuration_shape() {
        let transform = GuardTransform::new(default_config()).with_ip_banning(
            IpBanManager::new(),
            IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config"),
        );
        let printed = format!("{transform:?}");
        assert!(
            printed.starts_with("GuardTransform"),
            "the debug shape names the transform: {printed}"
        );
        assert!(
            printed.contains("BanState"),
            "the ban state renders through its own Debug: {printed}"
        );
    }

    /// The empty `threat_ban_config`, typed so the `new` calls stay inferable.
    fn no_entries() -> Vec<(String, ThreatBanEntry)> {
        Vec::new()
    }
}
