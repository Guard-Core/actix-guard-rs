//! The WebSocket guard, ported from fastapi-guard `guard/websocket.py`
//! (`guard_websocket` / `_run_websocket_checks`): the guard checks an
//! upgrade request must pass before the handshake completes, mapped onto the
//! reference's close shapes.
//!
//! actix Web exposes no pre-accept WebSocket close frame: the upgrade
//! request arrives as a plain request the middleware chain sees before the
//! `101 Switching Protocols` is ever rendered, so a blocked handshake
//! answers like the Go sibling's net/http translation - a `403 Forbidden`
//! pre-accept rejection carrying the close shape on dedicated headers
//! ([`WS_CLOSE_CODE_HEADER`] / [`WS_CLOSE_REASON_HEADER`]). Starlette's
//! `WebSocketException(code, reason)` denial is the reference shape being
//! translated.
//!
//! The check sequence is the reference's:
//!
//! 1. an undeterminable client address fails the handshake closed under
//!    `fail_secure` ([`WS_CLOSE_CLIENT_ADDRESS_UNKNOWN`]);
//! 2. a live IP ban ([`WS_CLOSE_IP_BANNED`]);
//! 3. `is_ip_allowed`: the global IP gate lists and the country rules
//!    ([`WS_CLOSE_IP_NOT_ALLOWED`]; a whitelist match skips the countries);
//! 4. the rate limit over the `ws` endpoint ([`WS_CLOSE_RATE_LIMIT_EXCEEDED`];
//!    skipped for whitelisted IPs, exactly like the reference's
//!    `not config.whitelist` gate);
//! 5. penetration detection over the path, query, and header views - an
//!    upgrade carries no body ([`WS_CLOSE_SUSPICIOUS_ACTIVITY`]).
//!
//! The close codes are the reference's: every policy denial is
//! [`WS_1008_POLICY_VIOLATION`], an engine malfunction is
//! [`WS_1013_TRY_AGAIN_LATER`] ([`WS_CLOSE_SECURITY_CHECK_FAILED`]). The
//! engine primitives the sequence runs on are infallible, so the 1013 shape
//! is reachable through exactly the reference's remaining arm: the check
//! machinery panicking mid-handshake, which [`WebSocketGuard`] contains.
//!
//! Non-upgrade requests pass through untouched (the HTTP guard's domain).

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::{Error, HttpRequest, HttpResponse};
use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RequestSurfaces, ResolvedExclusions, resolve as resolve_exclusions,
    scan_request,
};
use guard_core_engine::geo::{CountryGate, GeoIpHandler, check_countries};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::ip_gate::{IpGateConfig, IpGateVerdict};
use guard_core_engine::rate_limit::RateLimiter;
use std::future::{Ready, ready};
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::task::{Context, Poll};

/// `WS_1008_POLICY_VIOLATION`: every policy denial's close code.
pub const WS_1008_POLICY_VIOLATION: u16 = 1008;

/// `WS_1013_TRY_AGAIN_LATER`: the engine-malfunction close code.
pub const WS_1013_TRY_AGAIN_LATER: u16 = 1013;

/// One of the reference's close shapes (the `WS_CLOSE_*` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketCloseReason {
    /// The WebSocket close code.
    pub code: u16,
    /// The close reason phrase.
    pub reason: &'static str,
}

/// `IP banned` - a live ban on the client IP.
pub const WS_CLOSE_IP_BANNED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP banned",
};

/// `IP not allowed` - the `is_ip_allowed` family: gate lists, country rules.
pub const WS_CLOSE_IP_NOT_ALLOWED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP not allowed",
};

/// `Rate limit exceeded` - the `ws` endpoint window crossed.
pub const WS_CLOSE_RATE_LIMIT_EXCEEDED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Rate limit exceeded",
};

/// `Client address could not be determined` - the fail-secure unknown
/// address denial.
pub const WS_CLOSE_CLIENT_ADDRESS_UNKNOWN: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Client address could not be determined",
};

/// `Security check failed` - the engine-malfunction denial, try again later.
pub const WS_CLOSE_SECURITY_CHECK_FAILED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1013_TRY_AGAIN_LATER,
    reason: "Security check failed",
};

/// `Suspicious activity detected` - a scanned view produced a threat.
pub const WS_CLOSE_SUSPICIOUS_ACTIVITY: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Suspicious activity detected",
};

/// The response header carrying the close code on a rejected handshake.
pub const WS_CLOSE_CODE_HEADER: &str = "X-Guard-WebSocket-Close";

/// The response header carrying the close reason on a rejected handshake.
pub const WS_CLOSE_REASON_HEADER: &str = "X-Guard-WebSocket-Close-Reason";

/// Whether the request is a WebSocket upgrade: an `Upgrade: websocket`
/// header plus an `upgrade` token in `Connection` (the token list may carry
/// other connections, e.g. `keep-alive, Upgrade`).
#[must_use]
pub fn is_websocket_upgrade(request: &HttpRequest) -> bool {
    let upgrade_ok = request
        .headers()
        .get("Upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"));
    if !upgrade_ok {
        return false;
    }
    request
        .headers()
        .get("Connection")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// Map a generic block answer onto the reference's close shapes - the
/// mapping the HTTP guard's domain uses when it renders a rejected
/// handshake for a verdict produced outside this module: `1013` for the
/// fail-secure 500, the rate-limit close for 429, the ban close for a
/// banned body, the suspicious close for a detection block, and everything
/// else the IP-not-allowed close (the `is_ip_allowed` family).
#[must_use]
pub fn websocket_close_for_status(status: u16, body: &str) -> WebSocketCloseReason {
    if status == StatusCode::INTERNAL_SERVER_ERROR.as_u16() {
        return WS_CLOSE_SECURITY_CHECK_FAILED;
    }
    if status == StatusCode::TOO_MANY_REQUESTS.as_u16() {
        return WS_CLOSE_RATE_LIMIT_EXCEEDED;
    }
    let lowered = body.to_ascii_lowercase();
    if lowered.contains("banned") {
        return WS_CLOSE_IP_BANNED;
    }
    if lowered.contains("suspicious") {
        return WS_CLOSE_SUSPICIOUS_ACTIVITY;
    }
    WS_CLOSE_IP_NOT_ALLOWED
}

/// The handles the upgrade check sequence runs on. Every handle is optional:
/// an absent handle skips its arm, and the sequence stays infallible (the
/// engine's ban, gate, limiter, and scan primitives report through plain
/// values, so the reference's Redis failure branches have no counterpart
/// here).
#[derive(Clone)]
pub struct WebSocketGuardConfig {
    detect_config: DetectConfig,
    ip_gate: Option<IpGateConfig>,
    ban_manager: Option<IpBanManager>,
    rate_limiter: Option<RateLimiter>,
    country_rules: Option<(CountryGate, Arc<dyn GeoIpHandler>)>,
    fail_secure: bool,
    exclusions: ResolvedExclusions,
}

/// Manual [`core::fmt::Debug`]: the geo handler is a trait object without
/// `Debug`, so the config prints its shape and stops
/// (`finish_non_exhaustive`), the crate's `BanState` convention.
impl core::fmt::Debug for WebSocketGuardConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebSocketGuardConfig")
            .field("detect_config", &self.detect_config)
            .field("ip_gate", &self.ip_gate)
            .field("ban_manager", &self.ban_manager)
            .field("rate_limiter", &self.rate_limiter)
            .field("fail_secure", &self.fail_secure)
            .field("exclusions", &self.exclusions)
            .finish_non_exhaustive()
    }
}

impl WebSocketGuardConfig {
    /// A config with no handles: only the penetration scan runs, and an
    /// unattributable upgrade passes (fail-open, the reference default).
    #[must_use]
    pub fn new(detect_config: DetectConfig) -> Self {
        Self {
            detect_config,
            ip_gate: None,
            ban_manager: None,
            rate_limiter: None,
            country_rules: None,
            fail_secure: false,
            exclusions: resolve_exclusions(None, None),
        }
    }

    /// Install the global IP gate (`whitelist`/`blacklist`/`exempt_ips`)
    /// the `is_ip_allowed` list arms evaluate.
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the ban manager the `is_ip_banned` arm consults.
    #[must_use]
    pub fn with_ip_banning(mut self, ban_manager: IpBanManager) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Install the rate limiter the `check_rate_limit_by_ip` arm records
    /// through (the `ws` endpoint key, the reference's `endpoint_path`).
    #[must_use]
    pub fn with_rate_limiting(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Install the country rules (`whitelist_countries`/`blocked_countries`
    /// resolved through [`parse_country_lists`](guard_core_engine::geo::parse_country_lists))
    /// and the [`GeoIpHandler`] they resolve countries through.
    #[must_use]
    pub fn with_country_rules(mut self, gate: CountryGate, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.country_rules = Some((gate, handler));
        self
    }

    /// Fail the handshake closed when the client address cannot be
    /// determined (the reference `fail_secure` arm).
    #[must_use]
    pub const fn with_fail_secure(mut self, fail_secure: bool) -> Self {
        self.fail_secure = fail_secure;
        self
    }

    /// Install global detection exclusions for the scan arm (the header set
    /// merges over the engine defaults; every other surface overrides).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: &DetectionExclusionConfig,
    ) -> Self {
        self.exclusions = resolve_exclusions(Some(detection_exclusions), None);
        self
    }
}

/// The upgrade request's scan inputs, extracted as owned strings so the
/// check sequence runs on plain data (and can be contained on panic).
#[derive(Debug, Clone, Default)]
struct WebSocketRequestParts {
    client_ip: Option<IpAddr>,
    url_path: String,
    query_params: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

impl WebSocketRequestParts {
    fn extract(request: &HttpRequest) -> Self {
        Self {
            client_ip: request.peer_addr().map(|peer| peer.ip()),
            url_path: request.path().to_owned(),
            query_params: parse_query_pairs(request.query_string()),
            headers: request
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
        }
    }
}

/// The `parse_qsl`-decoded query pairs (`+` is a space, percent escapes
/// decode, a malformed escape stays literal): the family's query surface.
fn parse_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    if raw_query.is_empty() {
        return Vec::new();
    }
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode_component(name), decode_component(value)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

fn decode_component(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if bytes.len() >= index + 3 => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push(u8::try_from(high * 16 + low).expect("hex pair"));
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The reference check sequence (`_run_websocket_checks`): ban arm, the
/// `is_ip_allowed` family, the `ws` rate limit, then the penetration scan
/// over path, query, and headers (an upgrade carries no body).
///
/// # Errors
///
/// The close shape the handshake must be rejected with. Unattributable
/// requests (`client_ip` absent) skip the stateful arms - there is no
/// identity to ban, gate, or limit - and stay detection-screened; under
/// [`WebSocketGuardConfig::with_fail_secure`] they are rejected outright.
pub fn run_websocket_checks(
    config: &WebSocketGuardConfig,
    client_ip: Option<IpAddr>,
    url_path: &str,
    query_params: &[(String, String)],
    headers: &[(String, String)],
) -> Result<(), WebSocketCloseReason> {
    if client_ip.is_none() && config.fail_secure {
        return Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN);
    }

    if let (Some(manager), Some(ip)) = (&config.ban_manager, client_ip)
        && manager.is_banned(ip)
    {
        return Err(WS_CLOSE_IP_BANNED);
    }

    let mut whitelisted = false;
    if let (Some(gate), Some(ip)) = (&config.ip_gate, client_ip) {
        match gate.evaluate(ip) {
            IpGateVerdict::Denied(_) => return Err(WS_CLOSE_IP_NOT_ALLOWED),
            IpGateVerdict::Allowed(decision) => whitelisted = decision.is_whitelisted,
        }
    }

    if let (Some((gate, handler)), Some(ip)) = (&config.country_rules, client_ip)
        && check_countries(ip, gate, handler.as_ref(), whitelisted).is_some()
    {
        return Err(WS_CLOSE_IP_NOT_ALLOWED);
    }

    if let (Some(limiter), Some(ip)) = (&config.rate_limiter, client_ip)
        && !whitelisted
        && !limiter.check(ip, Some("ws")).allowed
    {
        return Err(WS_CLOSE_RATE_LIMIT_EXCEEDED);
    }

    let surfaces = RequestSurfaces {
        url_path: Some(url_path),
        query_params,
        headers,
        content_type: "",
        raw_body: "",
    };
    let verdict = scan_request(&surfaces, &config.exclusions, &config.detect_config);
    if verdict.is_threat {
        return Err(WS_CLOSE_SUSPICIOUS_ACTIVITY);
    }
    Ok(())
}

/// [`run_websocket_checks`] contained: a panic anywhere in the sequence
/// (an injected [`GeoIpHandler`], a foreign handle) maps to the reference's
/// engine-malfunction close shape, `1013 Try again later`.
fn run_checks_guarded(
    config: &WebSocketGuardConfig,
    parts: &WebSocketRequestParts,
) -> Result<(), WebSocketCloseReason> {
    catch_unwind(AssertUnwindSafe(|| {
        run_websocket_checks(
            config,
            parts.client_ip,
            &parts.url_path,
            &parts.query_params,
            &parts.headers,
        )
    }))
    .unwrap_or(Err(WS_CLOSE_SECURITY_CHECK_FAILED))
}

/// The rejected handshake answer: `403 Forbidden` (pre-accept) carrying the
/// close shape on [`WS_CLOSE_CODE_HEADER`] / [`WS_CLOSE_REASON_HEADER`],
/// with the family's plain-text body naming the reason. The response is
/// rendered fresh per rejection; actix responses carry their own
/// `#[must_use]`.
#[must_use = "render the close response into the handshake answer"]
pub fn close_response(reason: WebSocketCloseReason) -> HttpResponse {
    let code = HeaderValue::from_str(&reason.code.to_string()).expect("numeric header value");
    HttpResponse::build(StatusCode::FORBIDDEN)
        .insert_header((
            HeaderName::from_bytes(WS_CLOSE_CODE_HEADER.as_bytes()).expect("static header name"),
            code,
        ))
        .insert_header((
            HeaderName::from_bytes(WS_CLOSE_REASON_HEADER.as_bytes()).expect("static header name"),
            HeaderValue::from_static(reason.reason),
        ))
        .content_type("text/plain; charset=utf-8")
        .body(format!("WebSocket connection rejected: {}", reason.reason))
}

/// The WebSocket upgrade guard as an actix Web middleware: upgrade requests
/// run the reference check sequence before the inner service (and the
/// handshake) ever see them; non-upgrade requests pass through untouched.
///
/// Mount it alongside (or inside) the HTTP [`crate::GuardTransform`] on the
/// application's WebSocket routes:
///
/// ```ignore
/// App::new()
///     .wrap(GuardTransform::new(default_config()))
///     .wrap(WebSocketGuard::new(WebSocketGuardConfig::new(default_config())))
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketGuard {
    config: Arc<WebSocketGuardConfig>,
}

impl WebSocketGuard {
    /// Build the guard from its handles.
    #[must_use]
    pub fn new(config: WebSocketGuardConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for WebSocketGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = WebSocketGuardService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(WebSocketGuardService {
            inner: service,
            config: Arc::clone(&self.config),
        }))
    }
}

/// The actix [`Service`](actix_web::dev::Service) produced by
/// [`WebSocketGuard::new_transform`].
pub struct WebSocketGuardService<S> {
    inner: S,
    config: Arc<WebSocketGuardConfig>,
}

impl<S> WebSocketGuardService<S> {
    /// The verdict an upgrade request gets before dispatch (also the
    /// programmatic seam: the same sequence the middleware runs). `Err`
    /// carries the close shape the handshake must be rejected with.
    pub fn upgrade_verdict(&self, request: &HttpRequest) -> Result<(), WebSocketCloseReason> {
        let parts = WebSocketRequestParts::extract(request);
        run_checks_guarded(&self.config, &parts)
    }
}

impl<S, B> Service<ServiceRequest> for WebSocketGuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<ServiceResponse, Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        if !is_websocket_upgrade(request.request()) {
            let future = self.inner.call(request);
            return Box::pin(async move {
                let response = future.await?;
                Ok(response.map_into_boxed_body())
            });
        }
        match self.upgrade_verdict(request.request()) {
            Ok(()) => {
                let future = self.inner.call(request);
                Box::pin(async move {
                    let response = future.await?;
                    Ok(response.map_into_boxed_body())
                })
            }
            Err(reason) => {
                let response = request.into_response(close_response(reason));
                Box::pin(ready(Ok(response)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{TestRequest, call_service, init_service};
    use guard_core_engine::geo::parse_country_lists;
    use guard_core_engine::rate_limit::RateLimitConfig;

    fn detect_config() -> DetectConfig {
        crate::default_config()
    }

    /// The route handler the clean and blocked upgrade tests share: one fn
    /// item, one routing instantiation, exercised by the clean test (the
    /// blocked test's handshake is rejected before dispatch).
    async fn upgraded() -> &'static str {
        "upgraded"
    }

    #[test]
    fn close_table_matches_the_reference() {
        assert_eq!(
            WS_CLOSE_IP_BANNED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP banned"
            }
        );
        assert_eq!(
            WS_CLOSE_IP_NOT_ALLOWED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP not allowed"
            }
        );
        assert_eq!(
            WS_CLOSE_RATE_LIMIT_EXCEEDED,
            WebSocketCloseReason {
                code: 1008,
                reason: "Rate limit exceeded"
            }
        );
        assert_eq!(
            WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
            WebSocketCloseReason {
                code: 1008,
                reason: "Client address could not be determined"
            }
        );
        assert_eq!(
            WS_CLOSE_SECURITY_CHECK_FAILED,
            WebSocketCloseReason {
                code: 1013,
                reason: "Security check failed"
            }
        );
        assert_eq!(
            WS_CLOSE_SUSPICIOUS_ACTIVITY,
            WebSocketCloseReason {
                code: 1008,
                reason: "Suspicious activity detected"
            }
        );
    }

    #[test]
    fn upgrade_detection_reads_both_headers() {
        let upgrade = |upgrade: &'static str, connection: Option<&'static str>| {
            let mut builder = TestRequest::get();
            if let Some(connection) = connection {
                builder = builder.append_header(("Connection", connection));
            }
            if !upgrade.is_empty() {
                builder = builder.append_header(("Upgrade", upgrade));
            }
            is_websocket_upgrade(&builder.to_http_request())
        };
        assert!(upgrade("websocket", Some("upgrade")));
        assert!(upgrade("WebSocket", Some("keep-alive, Upgrade")));
        assert!(!upgrade("websocket", Some("keep-alive")));
        assert!(!upgrade("websocket", None));
        assert!(!upgrade("h2c", Some("upgrade")));
        assert!(!upgrade("", Some("upgrade")));
    }
    #[test]
    fn close_for_status_maps_the_block_shapes() {
        assert_eq!(
            websocket_close_for_status(500, "Security check failed"),
            WS_CLOSE_SECURITY_CHECK_FAILED
        );
        assert_eq!(
            websocket_close_for_status(429, "Too many requests"),
            WS_CLOSE_RATE_LIMIT_EXCEEDED
        );
        assert_eq!(
            websocket_close_for_status(403, "IP address banned"),
            WS_CLOSE_IP_BANNED
        );
        assert_eq!(
            websocket_close_for_status(400, "Suspicious activity detected"),
            WS_CLOSE_SUSPICIOUS_ACTIVITY
        );
        assert_eq!(
            websocket_close_for_status(403, "Forbidden"),
            WS_CLOSE_IP_NOT_ALLOWED
        );
    }

    #[test]
    fn query_pairs_decode_like_parse_qsl() {
        assert_eq!(
            parse_query_pairs("q=%3Cscript%3E&x=a+b&flag&bad=%zz"),
            vec![
                (String::from("q"), String::from("<script>")),
                (String::from("x"), String::from("a b")),
                (String::from("flag"), String::new()),
                (String::from("bad"), String::from("%zz")),
            ]
        );
        assert_eq!(parse_query_pairs(""), Vec::<(String, String)>::new());
        assert_eq!(decode_component("caf%C3%A9"), "café");
    }

    #[test]
    fn clean_upgrade_passes_every_arm() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(
            run_websocket_checks(
                &config,
                Some("203.0.113.7".parse().expect("ip")),
                "/ws",
                &[],
                &[]
            ),
            Ok(())
        );
    }

    #[test]
    fn unknown_address_is_fail_open_by_default_and_fail_secure_on_request() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(run_websocket_checks(&config, None, "/ws", &[], &[]), Ok(()));
        let config = config.with_fail_secure(true);
        assert_eq!(
            run_websocket_checks(&config, None, "/ws", &[], &[]),
            Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN)
        );
    }

    #[test]
    fn ban_arm_answers_ip_banned() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_BANNED)
        );
    }

    #[test]
    fn gate_lists_answer_ip_not_allowed() {
        let blacklist = IpGateConfig::new([] as [&str; 0], ["203.0.113.0/24"], [] as [&str; 0])
            .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(blacklist);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let whitelist = IpGateConfig::new(
            ["198.51.100.0/24"] as [&str; 1],
            [] as [&str; 0],
            [] as [&str; 0],
        )
        .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(whitelist);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );
        let allowed: IpAddr = "198.51.100.4".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(allowed), "/ws", &[], &[]),
            Ok(())
        );
    }

    struct FixedCountry(&'static str);

    impl GeoIpHandler for FixedCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_owned())
        }
    }

    #[test]
    fn country_rules_answer_ip_not_allowed_and_whitelist_skips_them() {
        let gate = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_country_rules(gate, Arc::new(FixedCountry("DE")));
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let whitelist_gate = IpGateConfig::new([ip.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let country = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist_gate)
            .with_country_rules(country, Arc::new(FixedCountry("DE")));
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn rate_limit_arm_answers_rate_limit_exceeded_and_skips_whitelisted() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config()).with_rate_limiting(limiter);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_RATE_LIMIT_EXCEEDED)
        );

        let whitelist = IpGateConfig::new([ip.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist)
            .with_rate_limiting(limiter);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn scan_arm_answers_suspicious_activity() {
        let config = WebSocketGuardConfig::new(detect_config());
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/etc/passwd", &[], &[]),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[("cmd".to_owned(), String::from("$(whoami)"))],
                &[],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[],
                &[(
                    "x-inject".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
    }

    #[test]
    fn debug_prints_the_config_shape() {
        let config = WebSocketGuardConfig::new(detect_config()).with_fail_secure(true);
        let printed = format!("{config:?}");
        assert!(
            printed.starts_with("WebSocketGuardConfig"),
            "the debug shape names the config: {printed}"
        );
        assert!(printed.contains("fail_secure: true"), "{printed}");
    }

    #[test]
    fn detection_exclusions_shape_the_scan_arm() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["secret".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let config =
            WebSocketGuardConfig::new(detect_config()).with_detection_exclusions(&exclusions);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        // The excluded param name skips the scan entirely.
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[(
                    "secret".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
                &[],
            ),
            Ok(())
        );
        // Any other name scans.
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[(
                    "public".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
                &[],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
    }

    struct PanickingCountry;

    impl GeoIpHandler for PanickingCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            panic!("geo backend down");
        }
    }

    #[test]
    fn check_panic_maps_to_try_again_later() {
        let country = parse_country_lists([] as [&str; 0], ["US"]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_country_rules(country, Arc::new(PanickingCountry));
        let parts = WebSocketRequestParts {
            client_ip: Some("203.0.113.9".parse().expect("ip")),
            url_path: "/ws".to_owned(),
            query_params: Vec::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            run_checks_guarded(&config, &parts),
            Err(WS_CLOSE_SECURITY_CHECK_FAILED)
        );
    }

    #[test]
    fn close_response_carries_the_shape() {
        let response = close_response(WS_CLOSE_IP_BANNED);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(WS_CLOSE_CODE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1008")
        );
        assert_eq!(
            headers
                .get(WS_CLOSE_REASON_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("IP banned")
        );
    }

    #[actix_web::test]
    async fn poll_ready_forwards_through_the_transform() {
        let config = WebSocketGuardConfig::new(detect_config());
        let service = init_service(
            actix_web::App::new()
                .wrap(WebSocketGuard::new(config))
                .route("/ws", actix_web::web::get().to(upgraded)),
        )
        .await;
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(matches!(
            actix_web::dev::Service::poll_ready(&service, &mut cx),
            std::task::Poll::Ready(Ok(()))
        ));
    }

    #[actix_web::test]
    async fn blocked_upgrade_is_rejected_pre_accept() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        let service = init_service(
            actix_web::App::new()
                .wrap(WebSocketGuard::new(config))
                .route("/ws", actix_web::web::get().to(upgraded)),
        )
        .await;
        let request = TestRequest::get()
            .uri("/ws")
            .append_header(("Upgrade", "websocket"))
            .append_header(("Connection", "Upgrade"))
            .peer_addr(std::net::SocketAddr::new(ip, 443))
            .to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(WS_CLOSE_CODE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1008")
        );
        assert_eq!(
            response
                .headers()
                .get(WS_CLOSE_REASON_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("IP banned")
        );
    }

    #[actix_web::test]
    async fn clean_upgrade_reaches_the_handler() {
        let config = WebSocketGuardConfig::new(detect_config()).with_rate_limiting(
            RateLimiter::new(RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 10,
                rate_limit_window: 10,
                ..RateLimitConfig::default()
            })
            .expect("valid config"),
        );
        let service = init_service(
            actix_web::App::new()
                .wrap(WebSocketGuard::new(config))
                .route("/ws", actix_web::web::get().to(upgraded)),
        )
        .await;
        let request = TestRequest::get()
            .uri("/ws")
            .append_header(("Upgrade", "websocket"))
            .append_header(("Connection", "Upgrade"))
            .peer_addr("203.0.113.7:41000".parse().expect("addr"))
            .to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn non_upgrade_traffic_passes_through_untouched() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        let service = init_service(
            actix_web::App::new()
                .wrap(WebSocketGuard::new(config))
                .route("/ws", actix_web::web::get().to(|| async { "plain" })),
        )
        .await;
        // A banned client's plain request is not this guard's domain: the
        // HTTP guard screens it.
        let request = TestRequest::get()
            .uri("/ws")
            .peer_addr("203.0.113.9:41000".parse().expect("addr"))
            .to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
