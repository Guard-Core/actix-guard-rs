//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardTransform;
use crate::response;
use actix_web::body::MessageBody;
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{Error, HttpMessage, HttpRequest};
use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use guard_core_engine::body_scan::extract_body_scan_values;
use guard_core_engine::detect::Threat;
use guard_core_engine::ip_ban::RATE_LIMIT_CATEGORY;
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_engine::ip_gate::IpGateVerdict;
use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// An actix Web middleware that screens requests through the Guard engine
/// before forwarding them to the next service.
///
/// Built by [`GuardTransform::new_transform`](actix_web::dev::Transform::new_transform).
/// The next service is shared through an [`Rc`]: the body has to be buffered
/// and scanned before the inner service can be called with the rebuilt
/// request, so the scanning future must own it, and the services actix Web
/// hands to a middleware are not `Clone`. actix Web builds its service tree
/// per worker (single-threaded event loops), so the `Rc` costs nothing and
/// never crosses threads.
pub struct GuardService<S> {
    next: Rc<S>,
    transform: GuardTransform,
}

impl<S> GuardService<S> {
    pub(crate) fn new(next: S, transform: GuardTransform) -> Self {
        Self {
            next: Rc::new(next),
            transform,
        }
    }
}

impl<S> Clone for GuardService<S> {
    fn clone(&self) -> Self {
        Self {
            next: Rc::clone(&self.next),
            transform: self.transform.clone(),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GuardService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardService")
            .field("next", &self.next)
            .field("transform", &self.transform)
            .finish()
    }
}

/// Why a request body could not be fully buffered.
enum BufferFailure {
    /// The body exceeded the buffering cap; reading stopped early.
    TooLarge,
    /// The body stream errored mid-read. The underlying error is dropped on
    /// purpose: it is body-transport noise (client abort, socket reset), not
    /// a security signal, and it must not leak into the `500` response.
    Read,
}

/// The outcome of scanning one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// No view tripped the engine.
    Clean,
    /// At least one view was flagged as a threat; the detection categories
    /// of the first flagged view, deduplicated and sorted (the auto-ban
    /// engine counts them per client IP).
    Threat(Vec<String>),
    /// The engine panicked; fail secure.
    Failed,
}

impl<S, B> Service<ServiceRequest> for GuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.next.poll_ready(cx)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let next = Rc::clone(&self.next);
        let transform = self.transform.clone();
        Box::pin(async move {
            let (request, payload) = request.into_parts();

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever passes.
            if let Some(response) = enforce_ip_gate(&request, &transform) {
                return Ok(response);
            }

            // The stateful stage (dynamic bans, then rate limiting) runs on
            // every attributed, non-exempt request before a body buffer is
            // spent on it.
            if let Some(response) = enforce_state_stage(&request, &transform) {
                return Ok(response);
            }

            let buffered = match buffer_body(payload, transform.body_cap()).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => return Ok(response::oversize(request)),
                Err(BufferFailure::Read) => return Ok(response::failure(request)),
            };
            match scan_request(&request, buffered.as_ref(), &transform) {
                ScanOutcome::Clean => {
                    // actix Web consumes the payload while buffering, so the
                    // request the next service sees is rebuilt around the
                    // buffered bytes (see the crate docs on request rebuilding).
                    let rebuilt = ServiceRequest::from_parts(
                        request,
                        Payload::from(buffered.unwrap_or_default()),
                    );
                    next.call(rebuilt)
                        .await
                        .map(ServiceResponse::map_into_boxed_body)
                }
                ScanOutcome::Threat(categories) => {
                    Ok(detect_block(&request, &transform, &categories))
                }
                ScanOutcome::Failed => Ok(response::failure(request)),
            }
        })
    }
}

/// Apply the configured IP gate to the request.
///
/// Returns the `403 Forbidden` response when the gate denies the request IP
/// (the request's peer address). A passed request gets the gate's
/// [`IpGateDecision`] inserted into the request extensions (the family-local
/// skip state, the equivalent of the reference engine's `state.is_whitelisted`
/// / `state.is_exempt`) so downstream handlers can read it. Without a gate or
/// without a peer address the request is not attributed: the gate does not
/// run, and nothing is inserted.
fn enforce_ip_gate(request: &HttpRequest, transform: &GuardTransform) -> Option<ServiceResponse> {
    let gate = transform.ip_gate()?;
    let peer = request.peer_addr()?;
    match gate.evaluate(peer.ip()) {
        IpGateVerdict::Allowed(decision) => {
            request.extensions_mut().insert(decision);
            None
        }
        IpGateVerdict::Denied(_) => Some(response::forbidden(request.clone())),
    }
}

/// The client IP, when the request is attributable and not skipped by the
/// `exempt_ips` contract: the stateful stage's gate.
///
/// Unattributed requests cannot be banned, rate limited, or counted (the
/// stage cannot tell who to hold responsible); whitelisted and exempt IPs
/// skip exactly what the reference skips for a whitelist match. Detection
/// applies to both, always.
fn attributed_and_counting(request: &HttpRequest) -> Option<IpAddr> {
    let peer = request.peer_addr()?;
    let decision = request
        .extensions()
        .get::<IpGateDecision>()
        .copied()
        .unwrap_or_default();
    if decision.is_whitelisted || decision.is_exempt {
        return None;
    }
    Some(peer.ip())
}

/// The stateful stage: dynamic bans, then rate limiting, in the reference
/// pipeline's order (an IP ban check precedes the rate limiter).
///
/// Returns the block response when the stage denies the request:
/// `403 Forbidden` (`IP address banned`) for a live ban,
/// `429 Too Many Requests` with `Retry-After: <window>` for a crossing.
fn enforce_state_stage(
    request: &HttpRequest,
    transform: &GuardTransform,
) -> Option<ServiceResponse> {
    let ip = attributed_and_counting(request)?;

    // Ban check first: a banned IP is denied before its rate window is
    // touched, so banned traffic neither consumes budget nor counts
    // violations (the request never reaches the limiter).
    if let Some(ban) = transform.ban_state()
        && ban.config.enable_ip_banning
        && ban.manager.is_banned(ip)
    {
        return Some(response::banned_ip(request.clone()));
    }

    let limiter = transform.rate_limiter()?;
    let decision = limiter.check(ip, None);
    if decision.allowed {
        return None;
    }
    // Rate-limit autoban: every active crossing counts one `rate_limit`
    // violation toward the auto-ban engine (the reference's
    // `_record_rate_limit_autoban`). The response stays 429; the ban takes
    // effect on the next request, which the ban stage answers with 403.
    if limiter.config().enable_rate_limit_auto_ban
        && let Some(ban) = transform.ban_state()
    {
        ban.register_violations(ip, &[RATE_LIMIT_CATEGORY], "rate_limit_exceeded");
    }
    Some(response::rate_limited(
        request.clone(),
        decision.retry_after(),
    ))
}

/// The detection block for one flagged request, with the auto-ban engine
/// attached: the flagged view's categories count as violations for the
/// client IP, and a crossed threshold bans on the spot (the reference
/// pipeline's suspicious-activity stage). Banning configured and fired
/// answers `IP has been banned`; everything else keeps the family's
/// `Suspicious activity detected` block shape.
fn detect_block(
    request: &HttpRequest,
    transform: &GuardTransform,
    categories: &[String],
) -> ServiceResponse {
    // Counting is attribute-gated only: the engine's resolution refuses to
    // ban while the config's enable_ip_banning is off, and the violations
    // still count (enabling banning later starts from observed history).
    if let (Some(ban), Some(ip)) = (transform.ban_state(), attributed_and_counting(request)) {
        let category_refs: Vec<&str> = categories.iter().map(String::as_str).collect();
        if ban
            .register_violations(ip, &category_refs, "penetration_attempt")
            .is_some()
        {
            return response::activity_banned(request.clone());
        }
    }
    response::blocked(request.clone())
}

/// Deduplicate and sort the flagged view's categories: the deterministic
/// order the auto-ban engine resolves thresholds in (the Go port sorts too).
fn sort_categories(mut categories: Vec<String>) -> Vec<String> {
    categories.sort_unstable();
    categories.dedup();
    categories
}

/// Buffer a request body up to `cap` bytes.
///
/// `Ok(None)` means the body was empty. The payload is polled directly
/// (`Payload` is `Unpin` and implements `Stream`) so no extra stream utility
/// crate is needed for a single `next()`.
async fn buffer_body(mut payload: Payload, cap: usize) -> Result<Option<Bytes>, BufferFailure> {
    let mut buffered = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| Pin::new(&mut payload).poll_next(cx)).await {
        let chunk = chunk.map_err(|_error| BufferFailure::Read)?;
        if buffered.len() + chunk.len() > cap {
            return Err(BufferFailure::TooLarge);
        }
        buffered.extend_from_slice(&chunk);
    }
    Ok(if buffered.is_empty() {
        None
    } else {
        Some(buffered.freeze())
    })
}

/// Run the engine over every request view, recovering from engine panics.
///
/// The engine's `detect` is total by signature, so the only failure mode is a
/// panic. Catching it here keeps the worker alive and lets the guard answer
/// `500` instead of unwinding out of the request future.
fn scan_request(
    request: &HttpRequest,
    body: Option<&Bytes>,
    transform: &GuardTransform,
) -> ScanOutcome {
    match catch_unwind(AssertUnwindSafe(|| scan_views(request, body, transform))) {
        Ok(ScanOutcome::Threat(categories)) => ScanOutcome::Threat(sort_categories(categories)),
        Ok(outcome) => outcome,
        Err(_) => ScanOutcome::Failed,
    }
}

/// One engine call per view, in the documented order: path, query, headers,
/// body. The first view the engine flags wins, and its categories are the
/// violation categories the auto-ban engine counts.
fn scan_views(
    request: &HttpRequest,
    body: Option<&Bytes>,
    transform: &GuardTransform,
) -> ScanOutcome {
    let path = request.path();
    if path != "/"
        && let Some(categories) = categories_for(transform, path, "url_path")
    {
        return ScanOutcome::Threat(categories);
    }

    let query = request.query_string();
    if !query.is_empty()
        && let Some(categories) = categories_for(transform, query, "query_param")
    {
        return ScanOutcome::Threat(categories);
    }

    for (name, value) in request.headers() {
        if is_excluded_header(name.as_str()) {
            continue;
        }
        // Opaque (non-ASCII) header values cannot be represented as `&str`.
        // They are skipped rather than guessed at, mirroring the string-typed
        // header maps the TypeScript adapters hand to the engine.
        let Ok(value) = value.to_str() else {
            continue;
        };
        if let Some(categories) = categories_for(transform, value, "header") {
            return ScanOutcome::Threat(categories);
        }
    }

    if let Some(bytes) = body {
        // Content-type routing (urlencoded fields, multipart parts, JSON
        // walks, blob fallback) happens in the engine; every extracted value
        // is scanned with its reference context instead of the lossy
        // whole-body blob.
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if let Some(categories) = body_categories(transform, content_type, bytes) {
            return ScanOutcome::Threat(categories);
        }
    }

    ScanOutcome::Clean
}

/// Scan the buffered request body through the engine's body-value extraction
/// (`request_body` view).
///
/// Every extracted value goes through the normal detect path with the context
/// label the reference engine scans it under (`request_body:form_field`,
/// `request_body:multipart_field`, `:embedded_json` leaves, ...); the first
/// threat wins. A value with a forced category (a JSON mongo operator key the
/// reference reports straight from the JSON walk) is a threat outright. An
/// empty (or whitespace-only) body is not scanned, mirroring the previous
/// behavior.
fn body_categories(
    transform: &GuardTransform,
    content_type: Option<&str>,
    bytes: &[u8],
) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return None;
    }
    for value in extract_body_scan_values(&text, content_type.unwrap_or(""), transform.config()) {
        if let Some(forced) = value.forced_category {
            return Some(vec![forced.to_owned()]);
        }
        if let Some(categories) = categories_for(transform, &value.content, &value.context) {
            return Some(categories);
        }
    }
    None
}

/// One engine call: the flagged view's threat categories, or `None` when the
/// engine clears the content. Regex threats carry the pattern table's
/// category; semantic threats carry their attack type.
fn categories_for(transform: &GuardTransform, content: &str, view: &str) -> Option<Vec<String>> {
    let verdict = (transform.detect_fn())(content, view, transform.config());
    if !verdict.is_threat {
        return None;
    }
    Some(
        verdict
            .threats
            .iter()
            .map(|threat| match threat {
                Threat::Regex(regex) => regex.category.clone(),
                Threat::Semantic(semantic) => semantic.attack_type.clone(),
            })
            .collect(),
    )
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE, default_config};
    use actix_web::body::MessageBody;
    use actix_web::dev::Transform;
    use actix_web::error::PayloadError;
    use actix_web::test::TestRequest;
    use actix_web::{Error, HttpResponse};
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};

    fn panicking_detect(_content: &str, _context: &str, _config: &DetectConfig) -> DetectVerdict {
        panic!("engine exploded");
    }

    async fn guarded(transform: GuardTransform) -> GuardService<OkService> {
        transform
            .new_transform(OkService)
            .await
            .expect("infallible")
    }

    fn body_text(response: ServiceResponse) -> String {
        let bytes = response.into_body().try_into_bytes().expect("bytes");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[actix_web::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let guard =
            guarded(GuardTransform::new(default_config()).with_detect_fn(panicking_detect)).await;
        let request = TestRequest::post()
            .uri("/hello")
            .set_payload("ping")
            .to_srv_request();

        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(body_text(response), FAILURE_MESSAGE);
    }

    #[actix_web::test]
    async fn scan_views_reports_threat_through_catch_unwind() {
        let transform = GuardTransform::new(default_config());
        let request = TestRequest::default()
            .uri("/files/../../etc/passwd")
            .to_http_request();
        assert_eq!(
            scan_request(&request, None, &transform),
            ScanOutcome::Threat(vec!["dir_traversal".to_owned()]),
            "traversal path should be flagged with its category"
        );
    }

    #[actix_web::test]
    async fn scan_views_sorts_and_dedups_categories() {
        let transform = GuardTransform::new(default_config());
        // `SELECT * FROM users` in a body view yields two sqli rows; the
        // outcome carries the category once.
        let request = TestRequest::post()
            .uri("/submit")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .to_http_request();
        let outcome = scan_request(
            &request,
            Some(&Bytes::from_static(b"SELECT * FROM users")),
            &transform,
        );
        assert_eq!(outcome, ScanOutcome::Threat(vec!["sqli".to_owned()]));
    }

    #[actix_web::test]
    async fn empty_body_is_not_scanned_and_still_forwarded() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let request = TestRequest::get().uri("/hello").to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    #[actix_web::test]
    async fn blocked_response_body_reports_the_documented_message() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 400);
        assert_eq!(body_text(response), BLOCKED_MESSAGE);
    }

    #[actix_web::test]
    async fn body_read_error_fails_secure_with_500() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let mut request = TestRequest::post().uri("/api/items").to_srv_request();
        request.set_payload(Payload::Stream {
            payload: Box::pin(FailingStream { yielded: false }),
        });

        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(body_text(response), FAILURE_MESSAGE);
    }

    #[actix_web::test]
    async fn a_body_at_the_cap_is_forwarded() {
        let guard = guarded(GuardTransform::new(default_config()).with_body_cap(4)).await;
        let request = TestRequest::post()
            .uri("/api/items")
            .set_payload("abcd")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    // --- body-value extraction through the full service ---

    async fn status_for(request: ServiceRequest) -> actix_web::http::StatusCode {
        let guard = guarded(GuardTransform::new(default_config())).await;
        guard.call(request).await.expect("response").status()
    }

    fn post_request(content_type: &str, payload: &'static [u8]) -> ServiceRequest {
        TestRequest::post()
            .uri("/submit")
            .insert_header(("content-type", content_type))
            .set_payload(payload)
            .to_srv_request()
    }

    #[actix_web::test]
    async fn sqli_in_a_form_field_is_blocked() {
        let request = post_request("application/x-www-form-urlencoded", b"q=1+OR+1%3D1");
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::BAD_REQUEST
        );
    }

    #[actix_web::test]
    async fn backslash_probe_in_a_form_field_is_blocked_through_the_raw_view() {
        let request = post_request("application/x-www-form-urlencoded", b"q=\\default");
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::BAD_REQUEST,
            "\\default in a form field must stay a recon probe"
        );
    }

    #[actix_web::test]
    async fn multipart_binary_island_smuggling_is_not_blocked() {
        // A binary-dense file part whose only printable fragment is shorter
        // than the minimum island run: no detection, request forwarded.
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"installer.zip\"\r\n\r\n");
        body.extend_from_slice(&noise_bytes(11, 4096));
        body.extend_from_slice(b"\x001 OR 1=1\x00");
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let request = post_request("multipart/form-data; boundary=B0", bytes_static(&body));
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::OK,
            "the compressed fragment must not pattern-match"
        );
    }

    #[actix_web::test]
    async fn plain_multipart_text_part_with_script_is_blocked() {
        let request = post_request(
            "multipart/form-data; boundary=B0",
            b"--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n",
        );
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::BAD_REQUEST
        );
    }

    #[actix_web::test]
    async fn embedded_json_leaf_attack_is_blocked() {
        let request = post_request(
            "application/x-www-form-urlencoded",
            br#"data={"a":"<script>alert(1)</script>"}"#,
        );
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::BAD_REQUEST
        );
    }

    #[actix_web::test]
    async fn mongo_operator_key_body_is_blocked() {
        let request = post_request("application/json", br#"{"$where": "1 OR 1=1"}"#);
        assert_eq!(
            status_for(request).await,
            actix_web::http::StatusCode::BAD_REQUEST
        );
    }

    #[actix_web::test]
    async fn benign_multipart_upload_is_forwarded() {
        let request = post_request(
            "multipart/form-data; boundary=B0",
            b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"\r\n\r\nhello world\r\n--B0--\r\n",
        );
        assert_eq!(status_for(request).await, actix_web::http::StatusCode::OK);
    }

    /// Copy `bytes` into a `'static` slice for `set_payload`.
    fn bytes_static(bytes: &[u8]) -> &'static [u8] {
        Bytes::copy_from_slice(bytes).to_vec().leak()
    }

    /// Deterministic pseudo-random bytes: the binary-dense fixture.
    fn noise_bytes(seed: u64, size: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(u8::try_from(state % 256).expect("value below 256"));
        }
        out
    }

    #[test]
    fn excluded_headers_cover_the_negotiation_set_and_sec_prefix() {
        for name in [
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "connection",
        ] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["sec-fetch-site", "sec-ch-ua", "sec-websocket-key"] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["cookie", "authorization", "content-type", "x-api-key"] {
            assert!(!is_excluded_header(name), "{name} should be scanned");
        }
    }

    // --- the global IP gate (exempt_ips contract checklist) ---

    use guard_core_engine::ip_gate::IpGateDecision;
    use std::net::IpAddr;
    use std::str::FromStr;

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    /// The checklist gate: a blacklisted exact IP and a blacklisted /24
    /// (192.0.2.x), an exempt exact IP and an exempt /28 (198.51.100.x), all
    /// disjoint.
    fn checklist_gate() -> crate::IpGateConfig {
        crate::IpGateConfig::new(
            NIL,
            ["203.0.113.9", "192.0.2.0/24"],
            ["198.51.100.7", "198.51.100.16/28"],
        )
        .expect("valid lists")
    }

    /// The downstream handler's view: the skip state in the request
    /// extensions, or `gate=off` when none was inserted.
    fn handler_verdict(request: &HttpRequest) -> String {
        match request.extensions().get::<IpGateDecision>().copied() {
            Some(decision) => format!(
                "gate=on wh={} ex={}",
                decision.is_whitelisted, decision.is_exempt
            ),
            None => "gate=off".to_owned(),
        }
    }

    fn gate_layer(gate: crate::IpGateConfig) -> GuardTransform {
        GuardTransform::new(default_config()).with_ip_gate(gate)
    }

    fn attributed(uri: &str, ip: &str) -> ServiceRequest {
        let peer = std::net::SocketAddr::new(IpAddr::from_str(ip).unwrap(), 45_000);
        TestRequest::get().uri(uri).peer_addr(peer).to_srv_request()
    }

    #[actix_web::test]
    async fn blacklisted_ip_is_denied_with_the_forbidden_body() {
        let guard = guarded(gate_layer(checklist_gate())).await;
        let response = guard
            .call(attributed("/hello", "203.0.113.9"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
        assert_eq!(body_text(response), FORBIDDEN_MESSAGE);

        // The blacklisted /24 denies its whole range.
        let guard = guarded(gate_layer(checklist_gate())).await;
        let response = guard
            .call(attributed("/hello", "192.0.2.77"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
        assert_eq!(body_text(response), FORBIDDEN_MESSAGE);
    }

    #[actix_web::test]
    async fn exempt_exact_and_cidr_ips_pass_with_the_skip_state_set() {
        // Checklist: exemption is observable behavior for the exact entry and
        // the CIDR member alike; the Rust family has no rate limiter yet, so
        // "skips rate limiting" is pinned at the flag level the contract
        // defines (the same state a whitelist match sets).
        let guard = guarded(gate_layer(checklist_gate())).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.7"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            handler_verdict(response.request()),
            "gate=on wh=false ex=true"
        );

        let guard = guarded(gate_layer(checklist_gate())).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.20"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            handler_verdict(response.request()),
            "gate=on wh=false ex=true"
        );
    }

    #[actix_web::test]
    async fn exempt_ip_on_the_blacklist_is_still_denied() {
        let gate =
            crate::IpGateConfig::new(NIL, ["198.51.100.7"], ["198.51.100.7"]).expect("valid lists");
        let guard = guarded(gate_layer(gate)).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.7"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
        assert_eq!(body_text(response), FORBIDDEN_MESSAGE);
    }

    #[actix_web::test]
    async fn exemption_never_opens_a_restrictive_whitelist() {
        let gate =
            crate::IpGateConfig::new(["192.0.2.1"], NIL, ["198.51.100.7"]).expect("valid lists");
        let guard = guarded(gate_layer(gate)).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.7"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
        assert_eq!(body_text(response), FORBIDDEN_MESSAGE);

        // An exempt-only config adds no deny path of its own: with the
        // whitelist empty, every IP passes, exempt or not.
        let exempt_only =
            crate::IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let guard = guarded(gate_layer(exempt_only)).await;
        let response = guard
            .call(attributed("/hello", "192.0.2.8"))
            .await
            .expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            handler_verdict(response.request()),
            "gate=on wh=false ex=false"
        );
    }

    #[actix_web::test]
    async fn whitelist_match_sets_both_flags() {
        let gate =
            crate::IpGateConfig::new(["198.51.100.7", "198.51.100.30"], NIL, ["198.51.100.7"])
                .expect("valid lists");
        let guard = guarded(gate_layer(gate)).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.7"))
            .await
            .expect("response");
        assert_eq!(
            handler_verdict(response.request()),
            "gate=on wh=true ex=true"
        );

        // A whitelist member outside exempt_ips: plain whitelist skip state.
        let gate = crate::IpGateConfig::new(["198.51.100.7", "198.51.100.30"], NIL, NIL)
            .expect("valid lists");
        let guard = guarded(gate_layer(gate)).await;
        let response = guard
            .call(attributed("/hello", "198.51.100.30"))
            .await
            .expect("response");
        assert_eq!(
            handler_verdict(response.request()),
            "gate=on wh=true ex=false"
        );
    }

    #[actix_web::test]
    async fn an_attack_from_an_exempt_ip_is_still_blocked_by_detection() {
        // Checklist: penetration detection still applies to exempt IPs.
        let guard = guarded(gate_layer(checklist_gate())).await;
        let peer = std::net::SocketAddr::new(IpAddr::from_str("198.51.100.7").unwrap(), 45_000);
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .peer_addr(peer)
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(body_text(response), BLOCKED_MESSAGE);
    }

    #[actix_web::test]
    async fn without_a_peer_address_the_gate_is_inert_and_detection_still_applies() {
        let guard = guarded(gate_layer(checklist_gate())).await;
        let request = TestRequest::get().uri("/hello").to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(handler_verdict(response.request()), "gate=off");

        // Not attributed does not mean unscreened: detection still scans.
        let guard = guarded(gate_layer(checklist_gate())).await;
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(body_text(response), BLOCKED_MESSAGE);
    }

    #[test]
    fn invalid_exempt_entry_fails_closed_at_config_time() {
        let error = crate::IpGateConfig::new(NIL, NIL, ["not-an-ip"]).unwrap_err();
        assert_eq!(error.list, "exempt_ips");
        assert_eq!(error.entry, "not-an-ip");
    }

    #[test]
    fn ipv4_mapped_peer_matches_v4_entries() {
        // Checklist: IPv4-mapped parity, same matching semantics as the
        // whitelist matcher.
        let mapped = IpAddr::from_str("::ffff:198.51.100.7").expect("mapped address");
        let gate = crate::IpGateConfig::new(["198.51.100.0/28"], NIL, ["198.51.100.7"])
            .expect("valid lists");
        assert!(matches!(
            gate.evaluate(mapped),
            IpGateVerdict::Allowed(decision) if decision.is_exempt
        ));
    }

    // --- the stateful stage: rate limiting, bans, auto-ban ---

    use crate::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, IpBanConfig, IpBanManager, RATE_LIMITED_MESSAGE,
        RateLimitConfig, RateLimiter, ThreatBanEntry,
    };
    use actix_web::http::StatusCode;
    use actix_web::http::header::RETRY_AFTER;
    use guard_core_engine::ip_ban::Clock;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The empty `threat_ban_config`, typed so the `new` calls stay inferable.
    fn no_entries() -> Vec<(String, ThreatBanEntry)> {
        Vec::new()
    }

    /// An enabled rate limiter with the given limit and auto-ban switch.
    fn limiter(limit: u32, auto_ban: bool) -> RateLimiter {
        #[allow(clippy::needless_update)] // forward-compatible against the pre-tier engine too
        RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: limit,
            rate_limit_window: 60,
            enable_rate_limit_auto_ban: auto_ban,
            ..RateLimitConfig::default()
        })
        .expect("valid config")
    }

    /// A fake clock (unix seconds starting at `1_000`) plus its handle, for
    /// deterministic ban-expiry coverage.
    fn fake_clock() -> (Clock, Arc<AtomicU64>) {
        let state = Arc::new(AtomicU64::new(1_000));
        let clock: Clock = {
            let seconds = state.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || seconds.load(Ordering::Relaxed) as f64)
        };
        (clock, state)
    }

    /// Status, body, and the `Retry-After` header of one guarded request.
    async fn full_status(
        transform: GuardTransform,
        request: ServiceRequest,
    ) -> (StatusCode, String, Option<String>) {
        let guard = guarded(transform).await;
        let response = guard.call(request).await.expect("response");
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().expect("ascii header").to_owned());
        (status, body_text(response), retry_after)
    }

    fn benign_request(ip: &str) -> ServiceRequest {
        attributed("/hello", ip)
    }

    fn attack_request(ip: &str) -> ServiceRequest {
        attributed("/files/../../etc/passwd", ip)
    }

    #[actix_web::test]
    async fn rate_limit_crossing_is_blocked_429_with_retry_after() {
        let transform = GuardTransform::new(default_config()).with_rate_limiting(limiter(2, false));
        for _ in 0..2 {
            let (status, _, retry_after) =
                full_status(transform.clone(), benign_request("192.0.2.55")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(retry_after, None, "allowed requests carry no Retry-After");
        }
        let (status, body, retry_after) =
            full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(
            retry_after.as_deref(),
            Some("60"),
            "Retry-After is the window"
        );
    }

    #[actix_web::test]
    async fn exempt_ip_exceeds_the_limit_and_still_gets_200() {
        // Checklist: the exempt flag is observable - exemption skips rate
        // limiting exactly like a whitelist match.
        let gate = crate::IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let (status, _, _) =
                full_status(transform.clone(), benign_request("198.51.100.7")).await;
            assert_eq!(status, StatusCode::OK, "exempt IPs are never rate limited");
        }
        // A non-exempt peer under the same config is limited as usual.
        let (status, _, retry_after) =
            full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after, None);
    }

    #[actix_web::test]
    async fn whitelisted_ip_is_also_skipped_by_the_limiter() {
        let gate = crate::IpGateConfig::new(["198.51.100.7"], NIL, NIL).expect("valid lists");
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let (status, _, _) =
                full_status(transform.clone(), benign_request("198.51.100.7")).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "whitelist match skips rate limiting"
            );
        }
    }

    #[actix_web::test]
    async fn unattributed_requests_are_not_rate_limited() {
        let transform = GuardTransform::new(default_config()).with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let request = TestRequest::get().uri("/hello").to_srv_request();
            let (status, _, _) = full_status(transform.clone(), request).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[actix_web::test]
    async fn banned_ip_is_blocked_with_the_banned_body() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let transform =
            GuardTransform::new(default_config()).with_ip_banning(manager.clone(), config);
        // Ban out of band through the shared handle (an operator or the
        // auto-ban engine did it).
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        let (status, body, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);

        // Other IPs are untouched.
        let (status, _, _) = full_status(transform, benign_request("192.0.2.56")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn ban_expiry_is_honored_for_a_short_duration() {
        let (clock, seconds) = fake_clock();
        let manager = IpBanManager::with_clock(clock);
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let transform =
            GuardTransform::new(default_config()).with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 5, "short")
            .expect("ban");
        let (status, body, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);

        seconds.store(1_000 + 6, Ordering::Relaxed);
        let (status, _, _) = full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK, "the ban expired");
    }

    #[actix_web::test]
    async fn banned_ip_blocks_before_detection_and_rate_limiting() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        // An attack from the banned IP: the ban stage wins over the
        // detection block shape...
        let (status, body, _) = full_status(transform.clone(), attack_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
        // ...and over the rate limiter: banned traffic never consumes budget.
        let (status, body, _) = full_status(transform, attack_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[actix_web::test]
    async fn detection_violations_ban_at_the_category_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let transform =
            GuardTransform::new(default_config()).with_ip_banning(IpBanManager::new(), config);

        // First violation: the plain block shape.
        let (status, body, _) = full_status(transform.clone(), attack_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE);
        // Second violation crosses the entry: banned on the spot.
        let (status, body, _) = full_status(transform.clone(), attack_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, ACTIVITY_BANNED_MESSAGE);
        // From then on the ban stage answers everything.
        let (status, body, _) = full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[actix_web::test]
    async fn enable_ip_banning_false_never_bans() {
        let config = IpBanConfig::new(
            false,
            1,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let transform =
            GuardTransform::new(default_config()).with_ip_banning(IpBanManager::new(), config);
        for _ in 0..3 {
            let (status, body, _) =
                full_status(transform.clone(), attack_request("192.0.2.55")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body, BLOCKED_MESSAGE,
                "banning is off: the plain block shape"
            );
        }
        let (status, _, _) = full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK, "nobody was banned");
    }

    #[actix_web::test]
    async fn exempt_ip_never_counts_detection_violations() {
        // Checklist: the exempt flag makes violation counting observable -
        // an exempt attacker can never be auto-banned.
        let gate = crate::IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let config = IpBanConfig::new(
            true,
            1,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config);
        for _ in 0..3 {
            let (status, body, _) =
                full_status(transform.clone(), attack_request("198.51.100.7")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body, BLOCKED_MESSAGE,
                "exempt violations are not counted, so no ban can fire"
            );
        }
    }

    #[actix_web::test]
    async fn rate_limit_autoban_is_off_by_default() {
        let config = IpBanConfig::new(true, 1, 3600, no_entries()).expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        for _ in 0..5 {
            let (status, body, _) =
                full_status(transform.clone(), benign_request("192.0.2.55")).await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(body, RATE_LIMITED_MESSAGE, "crossings stay rate limited");
        }
    }

    #[actix_web::test]
    async fn rate_limit_autoban_bans_at_the_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "rate_limit",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 30,
                },
            )],
        )
        .expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, true))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        // First crossing: violation 1, below the entry threshold.
        let (status, body, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        // Second crossing: violation 2 crosses the entry, the ban fires (the
        // response of this request is still the 429 it earned).
        let (status, _, _) = full_status(transform.clone(), benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // From then on the ban stage answers first.
        let (status, body, _) = full_status(transform, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    /// A body that yields one frame, then errors.
    struct FailingStream {
        yielded: bool,
    }

    impl Stream for FailingStream {
        type Item = Result<Bytes, PayloadError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.yielded {
                return Poll::Ready(Some(Err(PayloadError::EncodingCorrupted)));
            }
            self.yielded = true;
            Poll::Ready(Some(Ok(Bytes::from_static(b"hi"))))
        }
    }

    /// The inner service used by the unit tests: answers `200` with an empty
    /// body, and never inspects the request. It is only reachable on the
    /// benign paths these tests exercise.
    #[derive(Clone)]
    struct OkService;

    impl Service<ServiceRequest> for OkService {
        type Response = ServiceResponse;
        type Error = Error;
        type Future = std::future::Ready<Result<ServiceResponse, Error>>;

        fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&self, request: ServiceRequest) -> Self::Future {
            std::future::ready(Ok(request.into_response(HttpResponse::Ok().finish())))
        }
    }
}
