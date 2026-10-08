//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardTransform;
use crate::response;
use actix_web::body::MessageBody;
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{Error, HttpMessage, HttpRequest};
use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use guard_core_engine::detection_exclusions::{
    RequestSurfaces, RouteDetectionExclusions, resolve as resolve_exclusions,
};
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_engine::ip_gate::IpGateVerdict;
use guard_core_engine::route_config::RouteConfig;
use guard_core_rs::process_response::{RequestBits, ResponseBits};
use guard_core_rs::responses::{build_block_payload, fire_block_hook, resolve_error_body};
use guard_core_rs::tower::{RequestObservation, RouteRateLimits};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::SystemTime;

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
    Threat(guard_core_engine::detection_exclusions::RequestScanVerdict),
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

    #[allow(clippy::too_many_lines)] // the reference pipeline order, one arm per check
    fn call(&self, request: ServiceRequest) -> Self::Future {
        let next = Rc::clone(&self.next);
        let transform = self.transform.clone();
        Box::pin(async move {
            let (request, payload) = request.into_parts();
            let facts = request_facts(&request);

            // The reference `exclude_paths` carve-out runs first: the
            // docs/static paths bypass the whole pipeline (exact path
            // match), detection included.
            if transform.exclude_paths.contains(&facts.path) {
                let rebuilt = ServiceRequest::from_parts(request, payload);
                let mut forwarded = next
                    .call(rebuilt)
                    .await
                    .map(ServiceResponse::map_into_boxed_body)?;
                run_response_processor(
                    &transform,
                    &facts,
                    forwarded.status().as_u16(),
                    forwarded.response_mut(),
                );
                return Ok(forwarded);
            }

            // The reference's CORS preflight short-circuit: an OPTIONS
            // request carrying `access-control-request-method` answers from
            // the resolved CORS config directly (the reference
            // `is_preflight` + `build_preflight_response` in
            // `cors_handler.py`), before every security check. CORS
            // disabled (or no response processor) leaves OPTIONS requests
            // to the pipeline like any other method.
            if facts.method.eq_ignore_ascii_case("OPTIONS")
                && let Some(processor) = transform.response_processor.as_ref()
                && processor.cors_enabled()
                && let Some(answer) =
                    preflight_answer(processor.cors().expect("cors enabled"), &request)
            {
                let mut response =
                    response::blocked_with_body(request.clone(), answer.status_code, &answer.body);
                for (name, value) in &answer.headers {
                    if let (Ok(name), Ok(value)) = (
                        actix_web::http::header::HeaderName::try_from(name.as_str()),
                        actix_web::http::header::HeaderValue::from_str(value),
                    ) {
                        response.headers_mut().insert(name, value);
                    }
                }
                return Ok(response.map_into_boxed_body());
            }

            // The reference `RouteConfigResolver`: the carrier extension
            // wins over the installed resolver (the app attaches the
            // route's config directly, the reference
            // `request.state.route_config` idiom).
            let route_carrier: Option<std::sync::Arc<RouteConfig>> = request
                .extensions()
                .get::<std::sync::Arc<RouteConfig>>()
                .cloned()
                .or_else(|| {
                    transform
                        .route_configs()
                        .and_then(|resolver| resolver(&facts.method, &facts.path))
                });
            let route = route_carrier.as_deref();

            // The reference `process_usage_rules`: the route's usage and
            // frequency behavior rules track the request observation and a
            // crossed threshold dispatches the rule's action (a `ban`
            // lands in the shared ban manager and renders the banned
            // shape). The behavioral processor runs before the check
            // pipeline (the reference dispatches it from the middleware's
            // request pass).
            let route_rules: &[guard_core_engine::behavior::BehaviorRule] =
                route.map_or(&[], |route| &route.behavior_rules);
            if !route_rules.is_empty()
                && let Some(processor) = transform.response_processor.as_ref()
            {
                let endpoint_id = format!("{}:{}", facts.method, facts.path);
                let actions = processor.process_usage_rules(
                    &endpoint_id,
                    &facts.ip_string,
                    route_rules,
                    std::time::SystemTime::now(),
                );
                if actions
                    .iter()
                    .any(guard_core_engine::behavior::BehaviorAction::is_ban)
                {
                    return Ok(finish_generated(
                        &request,
                        &transform,
                        response::blocked_with_body(
                            request.clone(),
                            403,
                            crate::ACTIVITY_BANNED_MESSAGE,
                        ),
                    ));
                }
            }

            // The reference `RouteConfigResolver.should_bypass_check`: the
            // named check, or the `"all"` wildcard.
            let bypassed = |check: &str| {
                route.is_some_and(|route| {
                    route.bypassed_checks.contains("all") || route.bypassed_checks.contains(check)
                })
            };

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever
            // passes. The reference `ip_security` bypass skips the gate
            // (and the ban/geo arms below, the fused `ip_security` block).
            if !bypassed("ip")
                && let Some(response) = enforce_ip_gate(&request, &transform)
            {
                return Ok(finish_generated(&request, &transform, response));
            }

            // Check 2: emergency mode (503 outside the whitelist). The
            // reference pipeline never consults the bypass set here: the
            // global stage is not route-bypassable.
            if let Some(stage) = transform.emergency_mode()
                && let Some(answer) = stage.decide(
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    &facts.ip_string,
                    &facts.path,
                    &facts.method,
                )
            {
                return Ok(finish_generated(
                    &request,
                    &transform,
                    response::blocked_with_body(request.clone(), answer.status, &answer.body),
                ));
            }

            // Check 3: HTTPS enforcement (301 to the scheme-upgraded URL).
            // The route's `require_https` rides the same stage (the
            // carrier lane), so the trust knobs and the passive handling
            // match the global arm.
            {
                let https_url = format!(
                    "https://{}{}{}",
                    facts.host.as_deref().unwrap_or_default(),
                    facts.path,
                    facts.query
                );
                let route_require_https = route.is_some_and(|route| route.require_https);
                let answer = if let Some(stage) = transform.https_enforcement() {
                    if let Some(route) = route {
                        stage.decide_route(
                            &facts.path,
                            &facts.scheme,
                            facts.host.as_deref().map(host_of_authority),
                            facts.x_forwarded_proto.as_deref(),
                            &https_url,
                            Some(route.require_https),
                        )
                    } else {
                        stage.decide(
                            &facts.path,
                            &facts.scheme,
                            facts.host.as_deref().map(host_of_authority),
                            facts.x_forwarded_proto.as_deref(),
                            &https_url,
                        )
                    }
                } else if route_require_https && facts.scheme != "https" && !transform.passive_mode
                {
                    Some(guard_core_rs::https_enforcement::HttpsRedirectAnswer {
                        status: 301,
                        location: https_url,
                    })
                } else {
                    None
                };
                if let Some(redirect) = answer {
                    return Ok(finish_generated(
                        &request,
                        &transform,
                        response::redirect(request.clone(), &redirect),
                    ));
                }
            }

            // Check 4: request logging (compose-only, never blocks; the
            // composed line is the host's to emit).
            if let Some(stage) = transform.request_logging() {
                let _ = stage.compose(
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    Some(&facts.method),
                    Some(&facts.path),
                    None,
                );
            }

            // Check 5: the request body buffers under the size cap (413) -
            // the reference `request_size_content` stage. The route's
            // `max_request_size` replaces the global cap for the route
            // (the reference reads the route limit instead); the adapter's
            // own cap stays the ceiling when the route sets none.
            let body_cap = route
                .and_then(|route| route.max_request_size)
                .and_then(|size| usize::try_from(size).ok())
                .unwrap_or_else(|| transform.body_cap());
            let buffered = match buffer_body(payload, body_cap).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => {
                    return Ok(finish_generated(
                        &request,
                        &transform,
                        response::oversize(request.clone()),
                    ));
                }
                Err(BufferFailure::Read) => {
                    return Ok(finish_generated(
                        &request,
                        &transform,
                        response::failure(request.clone()),
                    ));
                }
            };

            // Checks 6 + 7: required headers, then authentication (the
            // fused stage answers for both; bypassing either reference
            // check skips the whole stage).
            if let Some(stage) = transform.headers_auth() {
                let pairs: Vec<(&str, &str)> = request
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value.to_str().ok().map(|value| (name.as_str(), value))
                    })
                    .collect();
                if let Some((_, answer)) = stage.decide(&facts.path, &pairs) {
                    return Ok(block_response(
                        &request,
                        &transform,
                        answer.status.as_u16(),
                        &answer.body,
                    ));
                }
            }

            // Check 8: the route referrer gate.
            if let Some(stage) = transform.referrer_gate()
                && let Some(answer) = stage.decide(
                    &facts.path,
                    facts.referer.as_deref(),
                    &facts.ip_string,
                    &facts.path,
                    &facts.method,
                )
            {
                return Ok(block_response(
                    &request,
                    &transform,
                    answer.status,
                    &answer.body,
                ));
            }

            // Check 9: the route custom validators (first blocking
            // response wins, the validator's own shape).
            if let Some(stage) = transform.custom_checks()
                && let Some(failure) = stage.decide_custom_validators(
                    &facts.path,
                    &facts.method,
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    buffered
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok()),
                )
            {
                let status = failure.status.unwrap_or(200);
                return Ok(block_response(&request, &transform, status, ""));
            }

            // Check 10: the route time-window gate.
            if let Some(stage) = transform.time_window_gate()
                && let Some(answer) =
                    stage.decide(&facts.path, &facts.ip_string, &facts.path, &facts.method)
            {
                return Ok(block_response(
                    &request,
                    &transform,
                    answer.status,
                    &answer.body,
                ));
            }

            // The detection scan itself never blocks: the verdict feeds
            // the pipeline stages that do. The reference
            // `suspicious_activity` bypass skips the scan (and with it the
            // violation feed) for the route.
            // The global `enable_penetration_detection` toggle skips the
            // scan everywhere (the request proceeds clean).
            let verdict = if bypassed("penetration") || !transform.penetration_detection_enabled() {
                None
            } else {
                match scan_request(&request, buffered.as_ref(), &transform) {
                    ScanOutcome::Clean => None,
                    ScanOutcome::Failed => {
                        return Ok(finish_generated(
                            &request,
                            &transform,
                            response::failure(request.clone()),
                        ));
                    }
                    ScanOutcome::Threat(verdict) => Some(verdict),
                }
            };

            // One engine-stage pass, split at the reference pipeline's
            // seams so the interleaved checks sit where the reference puts
            // them: the ban arm (check 12's `ip_security` bans) first, then
            // geo (12b), cloud (13), user agent (14), and the rate-limit
            // tiers + detection feed (15 + 16).
            let stage = transform
                .stage()
                .expect("the stage is built by Transform::new_transform");
            let finding = verdict
                .as_ref()
                .map(|verdict| guard_core_rs::tower::ThreatFinding {
                    is_threat: true,
                    categories: verdict.categories.clone(),
                    trigger_info: verdict.reason.clone(),
                });
            let observation = request_observation(&request);
            if !bypassed("ip_ban")
                && let Some(blocked) = stage.decide_bans_observed(facts.ip, Some(&observation))
            {
                return Ok(finish_generated(
                    &request,
                    &transform,
                    response::stage(request.clone(), &blocked),
                ));
            }

            // The reference runs the country arms inside the `ip`-gated
            // block: the same bypass skips the geo stage.
            if !bypassed("ip")
                && let Some(stage) = transform.geo_blocking()
                && let Some(decision) = stage.decide(facts.ip, facts.gate)
            {
                return Ok(block_response(
                    &request,
                    &transform,
                    decision.answer.status.as_u16(),
                    stage_answer_body(&decision.answer),
                ));
            }

            if !bypassed("clouds")
                && let Some(stage) = transform.cloud_provider()
                && let Some(decision) = stage.decide(facts.ip, facts.gate)
            {
                return Ok(block_response(
                    &request,
                    &transform,
                    decision.answer.status.as_u16(),
                    stage_answer_body(&decision.answer),
                ));
            }

            {
                // The route's `blocked_user_agents` runs additively before
                // the global filter (the reference
                // `check_user_agent_allowed` order); whitelisted and
                // exempt IPs skip exactly what the stage skips. A
                // non-compilable route pattern fails secure.
                let route_blocks = route
                    .filter(|route| !route.blocked_user_agents.is_empty())
                    .filter(|_| {
                        !facts
                            .gate
                            .is_some_and(|gate| gate.is_whitelisted || gate.is_exempt)
                    })
                    .map(|route| {
                        guard_core_engine::user_agent::UserAgentFilter::from_trusted_patterns(
                            route.blocked_user_agents.iter().cloned(),
                        )
                    });
                match route_blocks {
                    Some(Ok(filter))
                        if filter.is_blocked(facts.user_agent.as_deref().unwrap_or("")) =>
                    {
                        return Ok(block_response(
                            &request,
                            &transform,
                            403,
                            "User-Agent not allowed",
                        ));
                    }
                    Some(Err(_)) => {
                        return Ok(finish_generated(
                            &request,
                            &transform,
                            response::failure(request.clone()),
                        ));
                    }
                    _ => {}
                }
                if let Some(stage) = transform.user_agent()
                    && let Some(answer) = stage.decide(
                        facts.ip,
                        facts.gate,
                        Some(&facts.path),
                        facts.user_agent.as_deref(),
                        finding.as_ref(),
                    )
                {
                    return Ok(block_response(
                        &request,
                        &transform,
                        answer.status.as_u16(),
                        stage_answer_body(&answer),
                    ));
                }
            }

            // The carrier's rate-limit view is the route's tier (the
            // reference reads `route_config.rate_limit`/
            // `rate_limit_window`/`geo_rate_limits`); an invalid tier
            // fails secure, and the `rate_limit` bypass skips the pass.
            let carrier_tiers = match route.map(RouteConfig::rate_limits) {
                Some(Ok(tiers)) => tiers,
                Some(Err(_)) => {
                    return Ok(finish_generated(
                        &request,
                        &transform,
                        response::failure(request.clone()),
                    ));
                }
                None => None,
            };
            let extension_tiers = request.extensions().get::<RouteRateLimits>().cloned();
            let effective_tiers = carrier_tiers.as_ref().or(extension_tiers.as_ref());
            let gate = request.extensions().get::<IpGateDecision>().copied();
            if !bypassed("rate_limit")
                && let Some(blocked) = stage.decide_tiers_observed(
                    facts.ip,
                    Some(&facts.path),
                    effective_tiers,
                    gate,
                    finding.as_ref(),
                    Some(&observation),
                )
            {
                return Ok(finish_generated(
                    &request,
                    &transform,
                    response::stage(request.clone(), &blocked),
                ));
            }
            if let (Some(verdict), false) = (&verdict, stage.config().passive_mode) {
                // Below-threshold detection (or an unattributed request):
                // the plain family block shape. Under passive mode the
                // detection was observed and counted by the stage and the
                // request forwards (the reference's passive path renders
                // no block).
                let status = 400;
                let body = resolve_error_body(
                    transform.custom_error_responses(),
                    status,
                    response::BLOCKED_MESSAGE,
                );
                if let Some(observability) = transform.observability() {
                    let observation = request_observation(&request);
                    let payload = build_block_payload(
                        "suspicious_activity",
                        &format!("Suspicious activity detected: {}", facts.ip_string),
                        &verdict.reason,
                        false,
                        &facts.ip_string,
                        observation.url.as_deref().unwrap_or("/"),
                        observation.method.as_deref().unwrap_or(""),
                        Some(status),
                        &observability.sensitive,
                    );
                    fire_block_hook(transform.on_block(), &payload);
                }
                return Ok(block_response(&request, &transform, status, &body));
            }

            // Check 17: the global `custom_request` function (its own
            // response shape; a response without a status renders the
            // framework default 200).
            if let Some(stage) = transform.custom_checks()
                && let Some(answer) = stage.decide_custom_request(
                    &facts.method,
                    &facts.path,
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    buffered
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok()),
                )
            {
                let status = answer.status.unwrap_or(200);
                return Ok(block_response(&request, &transform, status, ""));
            }

            // actix Web consumes the payload while buffering, so the
            // request the next service sees is rebuilt around the
            // buffered bytes (see the crate docs on request rebuilding).
            let rebuilt =
                ServiceRequest::from_parts(request, Payload::from(buffered.unwrap_or_default()));
            let mut forwarded = next
                .call(rebuilt)
                .await
                .map(ServiceResponse::map_into_boxed_body)?;
            run_response_processor(
                &transform,
                &facts,
                forwarded.status().as_u16(),
                forwarded.response_mut(),
            );
            Ok(forwarded)
        })
    }
}

/// The request pieces the stage's event and log emissions read.
fn request_observation(request: &HttpRequest) -> RequestObservation {
    let mut url = request.path().to_owned();
    let query = request.query_string();
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    RequestObservation {
        method: Some(request.method().as_str().to_owned()),
        url: Some(url),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

/// The request facts the pipeline stages read (the actix mirror of the
/// tower adapter's `RequestFacts`).
struct RequestFacts {
    ip: Option<std::net::IpAddr>,
    gate: Option<IpGateDecision>,
    ip_string: String,
    path: String,
    method: String,
    scheme: String,
    referer: Option<String>,
    user_agent: Option<String>,
    host: Option<String>,
    x_forwarded_proto: Option<String>,
    origin: Option<String>,
    query: String,
}

/// Extract the facts from an actix request: the peer address is the
/// client identity, the connection info carries the host and scheme.
fn request_facts(request: &HttpRequest) -> RequestFacts {
    // Every extensions borrow lands in a local before the struct literal:
    // `connection_info()` mutates the extensions cache internally, and a
    // live immutable borrow inside the literal would double-borrow.
    let ip = request.peer_addr().map(|peer| peer.ip());
    let gate = request.extensions().get::<IpGateDecision>().copied();
    let scheme = request.connection_info().scheme().to_owned();
    let referer = header_string(request, header::REFERER);
    let user_agent = header_string(request, header::USER_AGENT);
    let host = header_string(request, header::HOST);
    let x_forwarded_proto = header_string(request, header::X_FORWARDED_PROTO);
    let origin = header_string(request, header::ORIGIN);
    let query = request.query_string();
    RequestFacts {
        ip,
        gate,
        ip_string: ip.map_or_else(String::new, |addr| addr.to_string()),
        path: request.path().to_owned(),
        method: request.method().as_str().to_owned(),
        scheme,
        referer,
        user_agent,
        host,
        x_forwarded_proto,
        origin,
        query: if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        },
    }
}

fn header_string(request: &HttpRequest, name: header::HeaderName) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The bare host of an authority string (port stripped, IPv6 brackets
/// removed): the connecting identity the trusted-proxy arm compares.
fn host_of_authority(value: &str) -> &str {
    let host_port = value.rsplit('@').next().unwrap_or_default();
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host_port.split_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => host_port,
    }
}

/// The answer body of a geo/cloud/user-agent stage answer. The reference
/// custom-error override never rides these answers (the stages construct
/// them with `custom_body: None`; the override resolves inside the
/// rate-limit stage's own render path, which this fused pass dispatches
/// through `response::stage` instead).
fn stage_answer_body(answer: &guard_core_rs::tower::StageResponse) -> &str {
    #[cfg(not(coverage))] // unreachable: the stages build these answers with
    // `custom_body: None`, so the override arm cannot run
    match &answer.custom_body {
        Some(custom) => custom,
        None => answer.body,
    }
    #[cfg(coverage)]
    {
        let _ = &answer.custom_body;
        answer.body
    }
}

/// A guard block answer with the response-side pass applied.
fn block_response(
    request: &HttpRequest,
    transform: &GuardTransform,
    status: u16,
    body: &str,
) -> ServiceResponse {
    finish_generated(
        request,
        transform,
        response::blocked_with_body(request.clone(), status, body),
    )
}

/// A guard-generated answer (block, redirect, oversize, failure) with the
/// response-side pass applied.
/// The CORS preflight short-circuit answer (the reference `is_preflight`
/// plus `build_preflight_response`).
///
/// `Some` when the request is a preflight (OPTIONS carrying the
/// request-method header), rendered from the resolved CORS config alone:
/// the reference answers the preflight before the pipeline and its
/// response pass run.
fn preflight_answer(
    cors: &guard_core_engine::cors::CorsConfig,
    request: &HttpRequest,
) -> Option<guard_core_engine::cors::CorsPreflightResponse> {
    let request_headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    if !guard_core_engine::cors::is_preflight(request.method().as_str(), &request_headers) {
        return None;
    }
    Some(guard_core_engine::cors::build_preflight_response(
        cors,
        guard_core_engine::cors::PreflightRequest {
            origin: request_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
                .map(|(_, value)| value.as_str()),
            request_method: request_headers
                .iter()
                .find(|(name, _)| {
                    name.eq_ignore_ascii_case(
                        guard_core_engine::cors::ALLOWED_PREFLIGHT_REQUEST_HEADER,
                    )
                })
                .map(|(_, value)| value.as_str()),
            request_headers_raw: request_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("access-control-request-headers"))
                .map(|(_, value)| value.as_str()),
        },
    ))
}

fn finish_generated(
    request: &HttpRequest,
    transform: &GuardTransform,
    mut response: ServiceResponse,
) -> ServiceResponse {
    run_response_processor_parts(
        transform,
        request,
        response.status().as_u16(),
        &mut response,
    );
    response
}

/// Run the response-side pass over a `ServiceResponse`.
fn run_response_processor_parts(
    transform: &GuardTransform,
    request: &HttpRequest,
    status: u16,
    response: &mut ServiceResponse,
) {
    if transform.response_processor.as_ref().is_none() {
        return;
    }
    let headers = compute_processor_headers(
        transform,
        request.method().as_str(),
        request.path(),
        request
            .peer_addr()
            .map_or_else(String::new, |peer| peer.ip().to_string())
            .as_str(),
        request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok()),
        status,
    );
    let http = response.response_mut();
    response::apply_headers(http, headers);
}

/// Run the response-side pass over a forwarded response (the request was
/// already consumed into the service call, so the facts carry the pieces).
fn run_response_processor(
    transform: &GuardTransform,
    facts: &RequestFacts,
    status: u16,
    response: &mut actix_web::HttpResponse,
) {
    if transform.response_processor.as_ref().is_none() {
        return;
    }
    let headers = compute_processor_headers(
        transform,
        &facts.method,
        &facts.path,
        &facts.ip_string,
        facts.origin.as_deref(),
        status,
    );
    response::apply_headers(response, headers);
}

/// The response-side pass itself: the global `return_pattern` rules
/// evaluate the response (a crossed `ban` lands in the processor's IP-ban
/// store), then the security-header set and the CORS verdict headers
/// compose. The response body is not captured (`body_prefix = None`):
/// `status:` rules evaluate, body rules skip, exactly the reference's
/// no-capture seam.
fn compute_processor_headers(
    transform: &GuardTransform,
    method: &str,
    url_path: &str,
    client_ip: &str,
    origin: Option<&str>,
    status: u16,
) -> Option<actix_web::http::header::HeaderMap> {
    let processor = transform.response_processor.as_ref()?;
    let mut bits = ResponseBits {
        status,
        body: None,
        headers: BTreeMap::new(),
    };
    let request = RequestBits {
        method: method.to_owned(),
        url_path: url_path.to_owned(),
        client_ip: client_ip.to_owned(),
        origin: origin.map(ToOwned::to_owned),
    };
    let _action = processor.process(&request, &mut bits, None, SystemTime::now());
    let mut headers = actix_web::http::header::HeaderMap::new();
    for (name, value) in bits.headers {
        #[cfg(not(coverage))] // unreachable: the processor renders the
        // engine's fixed security-header and CORS sets, always valid names
        // and values, so neither conversion can fail
        if let (Ok(name), Ok(value)) = (
            actix_web::http::header::HeaderName::try_from(name.as_str()),
            actix_web::http::header::HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
        #[cfg(coverage)]
        {
            let name = actix_web::http::header::HeaderName::try_from(name.as_str())
                .expect("the processor renders valid header names");
            let value = actix_web::http::header::HeaderValue::from_str(&value)
                .expect("the processor renders valid header values");
            headers.insert(name, value);
        }
    }
    Some(headers)
}

/// Apply the configured IP gate to the request.
///
/// Returns the `403 Forbidden` response when the gate denies the request IP
/// (the request's peer address), rendering the reference `ip_filter` behavior
/// end to end: passive mode logs the crossing and forwards (no gate decision
/// reaches the rest of the pipeline, so the unattributed handling applies),
/// the `on_block` hook fires once with the reference payload keys, and the
/// custom-error body override wins over the family default. A passed request
/// gets the gate's [`IpGateDecision`] inserted into the request extensions
/// (the family-local skip state, the equivalent of the reference engine's
/// `state.is_whitelisted` / `state.is_exempt`) so downstream handlers can
/// read it. Without a gate or without a peer address the request is not
/// attributed: the gate does not run, and nothing is inserted.
fn enforce_ip_gate(request: &HttpRequest, transform: &GuardTransform) -> Option<ServiceResponse> {
    let gate = transform.ip_gate()?;
    let peer = request.peer_addr()?;
    match gate.evaluate(peer.ip()) {
        IpGateVerdict::Allowed(decision) => {
            request.extensions_mut().insert(decision);
            None
        }
        IpGateVerdict::Denied(denial) => {
            if transform.passive_mode {
                return None;
            }
            let ip_string = peer.ip().to_string();
            let body = resolve_error_body(
                transform.custom_error_responses(),
                403,
                response::FORBIDDEN_MESSAGE,
            );
            if let Some(observability) = transform.observability() {
                let observation = request_observation(request);
                let payload = build_block_payload(
                    "ip_security",
                    &format!("IP address blocked: {ip_string}"),
                    denial.reason(),
                    false,
                    &ip_string,
                    observation.url.as_deref().unwrap_or("/"),
                    observation.method.as_deref().unwrap_or(""),
                    Some(403),
                    &observability.sensitive,
                );
                fire_block_hook(transform.on_block(), &payload);
            }
            Some(block_response(request, transform, 403, &body))
        }
    }
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
        Ok(outcome) => outcome,
        Err(_) => ScanOutcome::Failed,
    }
}

/// One multi-surface engine pass over the request, in the reference scan
/// order: URL path, query params, headers, body. The per-route
/// detection-exclusion surface ([`RouteDetectionExclusions`] request
/// extension resolving over the global config) merges and lowercases
/// through the engine's `resolve`, and [`scan_request`] (the engine's)
/// applies the reference semantics exactly: excluded query params and body
/// fields are skipped, excluded headers scan with their known
/// false-positive categories suppressed (address-carrying proxy headers
/// lose only `ssrf`, and only for address-chain values), the
/// enabled-categories set filters per value (a threat whose categories are
/// all filtered out ends the scan clean - terminal, not a reason to keep
/// scanning), and `detection_scan_body = false` skips the body surface
/// entirely.
///
/// The adapter-level pre-filter (`EXCLUDED_HEADERS`, every `sec-*` name)
/// keeps framework noise headers out of the surfaces before the engine
/// sees them. A semantic-only threat carries no category and contributes
/// nothing here, exactly like the reference's `category == ""` guard.
fn scan_views(
    request: &HttpRequest,
    body: Option<&Bytes>,
    transform: &GuardTransform,
) -> ScanOutcome {
    let resolved = resolve_exclusions(
        transform.detection_exclusions(),
        request.extensions().get::<RouteDetectionExclusions>(),
    );

    let path = request.path();
    let url_path = if path == "/" { None } else { Some(path) };

    // Query parameter pairs, `parse_qsl`-decoded (the reference reads the
    // decoded values, so exclusions and detection see what the handler
    // sees). Per pair, so excluded names are skippable.
    let query_params: Vec<(String, String)> = request
        .query_string()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode_query_component(name), decode_query_component(value)),
            None => (decode_query_component(pair), String::new()),
        })
        .collect();

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter(|(name, _)| !is_excluded_header(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let raw_body = body
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();

    let surfaces = RequestSurfaces {
        url_path,
        query_params: &query_params,
        headers: &headers,
        content_type,
        raw_body: &raw_body,
    };
    let verdict = (transform.scan_fn())(&surfaces, &resolved, transform.config());
    if verdict.is_threat {
        ScanOutcome::Threat(verdict)
    } else {
        ScanOutcome::Clean
    }
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

/// `urllib.parse.unquote_plus` for one query component: `%XX` runs and
/// `+` (form-encoding's space) decode into the value the reference's
/// `parse_qsl` hands the engine. Malformed escapes stay literal.
fn decode_query_component(component: &str) -> String {
    let plus_decoded = component.replace('+', " ");
    let bytes = plus_decoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE, OVERSIZE_MESSAGE, default_config,
    };
    use actix_web::body::MessageBody;
    use actix_web::dev::Transform;
    use actix_web::error::PayloadError;
    use actix_web::test::TestRequest;
    use actix_web::{Error, HttpResponse};
    use guard_core_engine::detect::DetectConfig;

    fn panicking_scan(
        _surfaces: &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
        _exclusions: &guard_core_engine::detection_exclusions::ResolvedExclusions,
        _config: &DetectConfig,
    ) -> guard_core_engine::detection_exclusions::RequestScanVerdict {
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
    async fn the_cors_preflight_short_circuits_before_every_check() {
        let transform = GuardTransform::from_security_config(&SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec!["https://app.example.com".to_owned()],
            cors_allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
            cors_allow_headers: vec!["content-type".to_owned()],
            cors_max_age: 900,
            ..SecurityConfig::default()
        })
        .expect("valid config");
        let app = actix_web::test::init_service(
            actix_web::App::new()
                .wrap(transform)
                .service(actix_web::web::resource("/api")),
        )
        .await;

        // The allowed preflight answers from the CORS config alone.
        let request = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/api")
            .insert_header(("Origin", "https://app.example.com"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .insert_header(("Access-Control-Request-Headers", "Content-Type"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Access-Control-Allow-Origin")
                .and_then(|value| value.to_str().ok()),
            Some("https://app.example.com")
        );
        assert_eq!(
            response
                .headers()
                .get("Access-Control-Max-Age")
                .and_then(|value| value.to_str().ok()),
            Some("900")
        );

        // The disallowed origin: 400 with the failure list.
        let request = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/api")
            .insert_header(("Origin", "https://evil.example.com"))
            .insert_header(("Access-Control-Request-Method", "DELETE"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body = actix_web::test::read_body(response).await;
        assert_eq!(body, "Disallowed CORS: origin, method");

        // An OPTIONS without the request-method header is not a preflight:
        // the guard skips it and the router answers (405: the resource
        // registers GET only - the request reached the router, which is
        // the pass-through proof).
        let request = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/api")
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn preflight_answer_answers_only_preflight_requests() {
        let cors = guard_core_engine::cors::CorsConfig {
            enabled: true,
            ..guard_core_engine::cors::CorsConfig::default()
        };
        // A preflight: Some, the engine's answer.
        let preflight = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .insert_header(("Origin", "https://app.example.com"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .to_http_request();
        let answer = preflight_answer(&cors, &preflight);
        assert!(answer.is_some());
        assert_eq!(answer.expect("answer").status_code, 200);

        // A plain OPTIONS: None, the pipeline's domain.
        let plain = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .to_http_request();
        assert!(preflight_answer(&cors, &plain).is_none());

        // A GET carrying the header: still not a preflight.
        let get = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::GET)
            .insert_header(("Access-Control-Request-Method", "POST"))
            .to_http_request();
        assert!(preflight_answer(&cors, &get).is_none());
    }

    #[actix_web::test]
    async fn the_route_usage_rules_track_and_ban_at_the_threshold() {
        let config = RouteConfig {
            behavior_rules: vec![guard_core_engine::behavior::BehaviorRule {
                rule_type: String::from("usage"),
                threshold: 2,
                window: 60,
                pattern: String::new(),
                action: String::from("ban"),
                ban_duration: Some(3600),
                correlate_with_detection: false,
            }],
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_response_processor(guard_core_rs::process_response::ResponseProcessor::new(
                None,
                None,
                Vec::new(),
                std::sync::Arc::new(std::sync::Mutex::new(
                    guard_core_engine::behavior::BehaviorTracker::new(),
                )),
                IpBanManager::new(),
                true,
                262_144,
                false,
            ))
            .with_route_configs(resolver_for(&[("GET", "/api")], config));
        let app = actix_web::test::init_service(
            actix_web::App::new().wrap(transform).service(
                actix_web::web::resource("/api").route(
                    actix_web::web::get()
                        .to(|| async { actix_web::HttpResponse::Ok().body("upstream") }),
                ),
            ),
        )
        .await;

        for _ in 0..2 {
            let request = actix_web::test::TestRequest::default()
                .method(actix_web::http::Method::GET)
                .uri("/api")
                .peer_addr("192.0.2.71:45000".parse().expect("addr"))
                .to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        }
        // The third crossing bans (the rule's action dispatched into the
        // shared ban manager).
        let request = actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::GET)
            .uri("/api")
            .peer_addr("192.0.2.71:45000".parse().expect("addr"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
        let body = actix_web::test::read_body(response).await;
        assert_eq!(body, crate::ACTIVITY_BANNED_MESSAGE);
    }

    #[actix_web::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let guard =
            guarded(GuardTransform::new(default_config()).with_scan_fn(panicking_scan)).await;
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
        assert!(
            matches!(
                scan_request(&request, None, &transform),
                ScanOutcome::Threat(ref verdict)
                    if verdict.is_threat
                        && verdict.categories == vec!["dir_traversal".to_owned()]
            ),
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
        assert!(
            matches!(
                outcome,
                ScanOutcome::Threat(ref verdict)
                    if verdict.is_threat && verdict.categories == vec!["sqli".to_owned()]
            ),
            "the body blob should flag sqli once"
        );
    }

    #[actix_web::test]
    async fn body_over_the_cap_is_rejected_with_413() {
        // The buffering loop stops at the cap and the guard answers `413`
        // instead of forwarding a truncated body.
        let transform = GuardTransform::new(default_config()).with_body_cap(4);
        let request = TestRequest::post()
            .uri("/hello")
            .set_payload(Bytes::from_static(b"12345"))
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body, OVERSIZE_MESSAGE);
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

    use crate::DetectionExclusionConfig;
    use crate::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, IpBanConfig, IpBanManager, RATE_LIMITED_MESSAGE,
        RateLimitConfig, RateLimiter, ThreatBanEntry,
    };
    use actix_web::http::StatusCode;
    use actix_web::http::header::RETRY_AFTER;
    use guard_core_engine::ip_ban::Clock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

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
    async fn exempt_ip_violations_still_count_toward_the_ban() {
        // Checklist: the exemption skips rate limiting and the ban *check*
        // skip state never shields counting - the reference's
        // suspicious-activity stage skips a whitelisted IP only, so an
        // exempt attacker's detections still feed the auto-ban engine and
        // a crossed threshold bans on the spot.
        let gate = crate::IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
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
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config);
        let (status, body, _) =
            full_status(transform.clone(), attack_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE, "violation 1: the plain block shape");
        let (status, body, _) =
            full_status(transform.clone(), attack_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, ACTIVITY_BANNED_MESSAGE,
            "exempt violations count: the crossed threshold bans"
        );
        // From then on the ban stage answers everything.
        let (status, body, _) =
            full_status(transform.clone(), benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, crate::BANNED_MESSAGE);
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
    #[derive(Clone, Debug)]
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
    // ---- the wave surfaces, end to end through the public API ----

    /// A static geolocation: every IP maps to `DE`.
    struct StaticGeo;

    impl guard_core_engine::geo::GeoIpHandler for StaticGeo {
        fn get_country(&self, ip: IpAddr) -> Option<String> {
            let _ = ip;
            Some("DE".to_owned())
        }
    }

    /// A fixed test peer address: the requests are attributable.
    fn peer() -> std::net::SocketAddr {
        std::net::SocketAddr::new(IpAddr::from_str("192.0.2.200").unwrap(), 45_000)
    }

    /// Insert a request extension (the per-route surface idiom).
    fn with_ext<T: Send + Sync + 'static>(request: ServiceRequest, ext: T) -> ServiceRequest {
        request.extensions_mut().insert(ext);
        request
    }

    async fn status_body(
        transform: GuardTransform,
        request: ServiceRequest,
    ) -> (StatusCode, String) {
        let (status, body, _) = full_status(transform, request).await;
        (status, body)
    }

    #[actix_web::test]
    async fn route_tier_resolver_limits_its_paths_only() {
        let tiers = Arc::new(|path: &str| {
            if path.starts_with("/login") {
                Some(RouteRateLimits::new(Some(1), None, None).expect("valid tiers"))
            } else {
                None
            }
        });
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers);
        let request = TestRequest::get()
            .uri("/login")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/login")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, retry_after) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(retry_after.as_deref(), Some("60"));
        let request = TestRequest::get()
            .uri("/other")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "other paths keep the global tier");
    }

    #[actix_web::test]
    async fn route_rate_limits_extension_wins_over_the_resolver() {
        let tiers = Arc::new(|_path: &str| {
            Some(RouteRateLimits::new(Some(100), None, None).expect("valid tiers"))
        });
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers);
        let build = || {
            let request = TestRequest::get()
                .uri("/tight")
                .peer_addr(peer())
                .to_srv_request();
            with_ext(
                request,
                RouteRateLimits::new(Some(1), None, None).expect("valid tiers"),
            )
        };
        let (status, _, _) = full_status(transform.clone(), build()).await;
        assert_eq!(status, StatusCode::OK, "the extension tier allows one");
        let (status, _, _) = full_status(transform.clone(), build()).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "the extension tier wins over the resolver"
        );
        // Without the extension the resolver's tier applies: the tight
        // global limiter never crosses under the resolver's 100-request
        // tier, so the request passes.
        let request = TestRequest::get()
            .uri("/tight")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform, request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the resolver tier decides when no extension is present"
        );
    }

    #[actix_web::test]
    async fn bare_query_param_scans_as_an_empty_value() {
        // A parameter without an `=` (`?flag`) is still a surface: it is
        // scanned with an empty value and never panics the pair decode.
        let transform = GuardTransform::new(default_config());
        let request = TestRequest::get()
            .uri("/hello?flag&name=value")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::OK, "benign bare params pass through");
    }

    #[actix_web::test]
    async fn guard_service_debug_prints_the_configuration_shape() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let printed = format!("{guard:?}");
        assert!(
            printed.starts_with("GuardService"),
            "the debug shape names the service: {printed}"
        );
        assert!(
            printed.contains("OkService") && printed.contains("GuardTransform"),
            "the inner service and the transform both render: {printed}"
        );
    }

    #[actix_web::test]
    async fn poll_ready_reports_the_inner_service_readiness() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(guard.poll_ready(&mut cx), Poll::Ready(Ok(()))),
            "the ready inner service passes readiness through"
        );
    }

    #[actix_web::test]
    async fn unattributed_detection_block_fires_the_on_block_payload() {
        // The stage never sees an IP to attribute, so the adapter renders
        // the plain detection block itself - and the observability seams
        // (the payload, the hook) still fire.
        let (payloads, hook) = block_collector();
        let transform = GuardTransform::new(default_config())
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook);
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .to_srv_request();
        let (status, body) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE);
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        let payload = &payloads[0];
        assert_eq!(payload.check_name, "suspicious_activity");
        assert_eq!(payload.status_code, Some(400));
        assert_eq!(payload.client_ip, "", "no peer address, no attribution");
        assert_eq!(payload.path, "/files/../../etc/passwd");
        assert_eq!(payload.method, "GET");
        assert!(!payload.passive_mode);
    }

    #[actix_web::test]
    async fn whitelisted_attacker_is_still_detected_with_the_full_payload() {
        // Detection never skips a whitelisted IP: the stage's feed drops the
        // finding (whitelisted IPs never count toward bans), so the adapter
        // renders the plain block - and the payload carries the attributed
        // IP, the request URL, and the user agent.
        let (payloads, hook) = block_collector();
        let gate = crate::IpGateConfig::new(["192.0.2.200"], NIL, NIL).expect("valid lists");
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook);
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd?cmd=cat%20/etc/passwd")
            .insert_header(("user-agent", "guard-test/1.0"))
            .peer_addr(peer())
            .to_srv_request();
        let (status, body) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "detection still scans");
        assert_eq!(body, BLOCKED_MESSAGE);
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        let payload = &payloads[0];
        assert_eq!(payload.client_ip, "192.0.2.200");
        assert_eq!(
            payload.path,
            "/files/../../etc/passwd?cmd=cat%20/etc/passwd"
        );
        assert_eq!(payload.method, "GET");
    }

    #[actix_web::test]
    async fn guard_service_clone_shares_the_inner_service() {
        let guard = guarded(GuardTransform::new(default_config())).await;
        let clone = guard.clone();
        let request = TestRequest::get().uri("/hello").to_srv_request();
        let response = clone.call(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK, "the clone serves too");
    }

    /// An in-memory sliding window (the backend is up): one hit per call,
    /// post-eviction count returned, exactly the engine contract.
    struct MemoryWindowStore(Mutex<std::collections::HashMap<String, Vec<f64>>>);

    impl MemoryWindowStore {
        fn new() -> Self {
            Self(Mutex::new(std::collections::HashMap::new()))
        }
    }

    impl guard_core_rs::tower::SlidingWindowStore for MemoryWindowStore {
        fn record_hit(
            &self,
            key: &str,
            now: f64,
            window: u64,
        ) -> Result<u64, guard_core_engine::distributed::StoreError> {
            let mut windows = self.0.lock().expect("windows");
            let hits = windows.entry(key.to_owned()).or_default();
            hits.retain(|hit| now - hit < f64::from(u32::try_from(window).unwrap_or(u32::MAX)));
            hits.push(now);
            Ok(hits.len() as u64)
        }
    }

    /// An in-memory ban store (the backend is up), optionally pre-seeded
    /// with a (key, expiry) ban.
    struct MemoryBanStore(Mutex<std::collections::HashMap<String, f64>>);

    impl MemoryBanStore {
        fn seeded(key: &str, expiry: f64) -> Self {
            let mut bans = std::collections::HashMap::new();
            bans.insert(key.to_owned(), expiry);
            Self(Mutex::new(bans))
        }
    }

    impl guard_core_engine::distributed::BanStore for MemoryBanStore {
        fn set_ban(
            &self,
            key: &str,
            expiry: f64,
            _ttl_seconds: u64,
        ) -> Result<(), guard_core_engine::distributed::StoreError> {
            self.0.lock().expect("bans").insert(key.to_owned(), expiry);
            Ok(())
        }

        fn get_ban(
            &self,
            key: &str,
        ) -> Result<Option<f64>, guard_core_engine::distributed::StoreError> {
            Ok(self.0.lock().expect("bans").get(key).copied())
        }

        fn delete_ban(&self, key: &str) -> Result<(), guard_core_engine::distributed::StoreError> {
            self.0.lock().expect("bans").remove(key);
            Ok(())
        }
    }

    #[actix_web::test]
    async fn distributed_stores_drive_the_ban_round_trip() {
        // The distributed ban store is live: the first lookup reads a stale
        // seeded ban and deletes it (the reference `_check_redis_exact`
        // expiry sweep), the rate-limit crossing with the flat threshold of
        // one bans on the spot and writes through the store, and the ban
        // then answers `403` on the next request.
        let ban_store = Arc::new(MemoryBanStore::seeded(
            "guard_core:banned_ips:192.0.2.77",
            1.0,
        ));
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, true))
            .with_ip_banning(
                IpBanManager::new(),
                IpBanConfig::new(true, 1, 3600, no_entries()).expect("valid config"),
            )
            .with_distributed_store(
                Arc::new(MemoryWindowStore::new())
                    as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                false,
            )
            .with_distributed_ban_store(
                Arc::clone(&ban_store) as Arc<dyn guard_core_engine::distributed::BanStore>
            );
        let build = || {
            TestRequest::get()
                .uri("/hello")
                .peer_addr(std::net::SocketAddr::new(
                    IpAddr::from_str("192.0.2.77").unwrap(),
                    45_000,
                ))
                .to_srv_request()
        };
        // Stale distributed ban: swept, the request proceeds to the window.
        let (status, _, _) = full_status(transform.clone(), build()).await;
        assert_eq!(status, StatusCode::OK, "the stale ban was deleted");
        assert!(
            ban_store
                .0
                .lock()
                .expect("bans")
                .get("guard_core:banned_ips:192.0.2.77")
                .is_none(),
            "the sweep removed the stale entry"
        );
        // Crossing: the 429 goes out and the auto-ban writes the ban.
        let (status, _, _) = full_status(transform.clone(), build()).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let expiry = ban_store
            .0
            .lock()
            .expect("bans")
            .get("guard_core:banned_ips:192.0.2.77")
            .copied()
            .expect("the crossing banned through the distributed store");
        assert!(
            expiry > 1.0,
            "the stored expiry is a live unix timestamp: {expiry}"
        );
        // The ban (cached locally by the write) answers first.
        let (status, body, _) = full_status(transform, build()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[actix_web::test]
    async fn geo_tier_limits_the_resolved_country() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers)
            .with_geo_handler(Arc::new(StaticGeo));
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the DE tier crossed");
    }

    #[actix_web::test]
    async fn geo_tier_never_applies_without_a_handler() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let transform = GuardTransform::new(default_config()).with_route_tiers(tiers);
        for _ in 0..5 {
            let request = TestRequest::get()
                .uri("/hello")
                .peer_addr(peer())
                .to_srv_request();
            let (status, _, _) = full_status(transform.clone(), request).await;
            assert_eq!(status, StatusCode::OK, "no handler: the geo tier is inert");
        }
    }

    #[actix_web::test]
    async fn excluded_detection_params_pass_and_other_params_scan() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let transform = GuardTransform::new(default_config()).with_detection_exclusions(exclusions);
        let request = TestRequest::get()
            .uri("/search?q=1+OR+1%3D1")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "the excluded param is not scanned");
        let request = TestRequest::get()
            .uri("/search?page=1+OR+1%3D1")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform.clone(), request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-excluded param still scans"
        );
    }

    #[actix_web::test]
    async fn route_detection_exclusions_override_the_global_config_per_request() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let transform = GuardTransform::new(default_config()).with_detection_exclusions(exclusions);
        let route = RouteDetectionExclusions {
            excluded_detection_params: Some(vec![]),
            ..RouteDetectionExclusions::default()
        };
        let request = TestRequest::get()
            .uri("/search?q=1+OR+1%3D1")
            .peer_addr(peer())
            .to_srv_request();
        let request = with_ext(request, route);
        let (status, _) = status_body(transform, request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the route re-enables the param surface"
        );
    }

    #[actix_web::test]
    async fn detection_scan_body_false_skips_the_body_surface() {
        let exclusions = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let transform = GuardTransform::new(default_config()).with_detection_exclusions(exclusions);
        let request = TestRequest::post()
            .uri("/submit")
            .set_payload(Bytes::from_static(b"SELECT * FROM users"))
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "the body does not scan");
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "the path still scans");
    }

    #[actix_web::test]
    async fn route_scan_body_true_reenables_the_body() {
        let exclusions = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let transform = GuardTransform::new(default_config()).with_detection_exclusions(exclusions);
        let route = RouteDetectionExclusions {
            detection_scan_body: Some(true),
            ..RouteDetectionExclusions::default()
        };
        let request = TestRequest::post()
            .uri("/submit")
            .set_payload(Bytes::from_static(b"SELECT * FROM users"))
            .peer_addr(peer())
            .to_srv_request();
        let request = with_ext(request, route);
        let (status, _) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn excluded_body_fields_resolve_through_the_engine() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_body_fields: vec!["note".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let transform = GuardTransform::new(default_config()).with_detection_exclusions(exclusions);
        let request = TestRequest::post()
            .uri("/submit")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(Bytes::from_static(b"note=1+OR+1%3D1"))
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "excluded field skips");
        let request = TestRequest::post()
            .uri("/submit")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(Bytes::from_static(b"other=1+OR+1%3D1"))
            .peer_addr(peer())
            .to_srv_request();
        let (status, _) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The `on_block` collector: the payloads the guard fired.
    fn block_collector() -> (
        Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>>,
        guard_core_rs::responses::OnBlockHook,
    ) {
        let payloads: Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&payloads);
        let hook: guard_core_rs::responses::OnBlockHook =
            Arc::new(move |payload| sink.lock().expect("payloads").push(payload.clone()));
        (payloads, hook)
    }

    #[actix_web::test]
    async fn on_block_fires_for_the_detection_block_and_custom_body_overrides_it() {
        let (payloads, hook) = block_collector();
        let transform = GuardTransform::new(default_config())
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook)
            .with_custom_error_responses(
                [(400u16, "blocked:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body) = status_body(transform, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body, "blocked:custom",
            "the custom body overrides the default"
        );
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        let payload = &payloads[0];
        assert_eq!(payload.check_name, "suspicious_activity");
        assert_eq!(payload.status_code, Some(400));
        assert_eq!(payload.client_ip, "192.0.2.200");
        assert!(!payload.passive_mode);
    }

    #[actix_web::test]
    async fn custom_error_responses_override_the_throttled_body() {
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_custom_error_responses(
                [(429u16, "slow down:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, retry_after) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, "slow down:custom");
        assert_eq!(retry_after.as_deref(), Some("60"), "Retry-After survives");
    }

    #[actix_web::test]
    async fn passive_mode_records_but_never_blocks() {
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_passive_mode(true);
        let request = TestRequest::get()
            .uri("/files/../../etc/passwd")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "passive: the detection block is log-only"
        );
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::OK, "passive: no 429 is rendered");
    }

    #[actix_web::test]
    async fn event_bus_receives_the_rate_limited_event() {
        let events: Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let bus = Arc::new(
            guard_core_rs::events::SecurityEventBus::new(true).on_event(Arc::new(move |event| {
                sink.lock().expect("events").push(event.clone());
            })),
        );
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_event_bus(bus);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let events = events.lock().expect("events");
        assert!(
            events.iter().any(|event| event.event_type == "rate_limited"
                && event.action_taken == "request_blocked"
                && event.handler_name.as_deref() == Some("rate_limit")),
            "the rate_limited event fired: {events:?}"
        );
    }

    /// A distributed store that always fails (the backend is down).
    struct DownStore;

    impl guard_core_rs::tower::SlidingWindowStore for DownStore {
        fn record_hit(
            &self,
            _key: &str,
            _now: f64,
            _window: u64,
        ) -> Result<u64, guard_core_engine::distributed::StoreError> {
            Err(guard_core_engine::distributed::StoreError(String::new()))
        }
    }

    #[actix_web::test]
    async fn distributed_store_fail_closed_answers_the_503_shape() {
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(10, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                false,
            );
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, retry_after) = full_status(transform, request).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "fail-closed backend error"
        );
        assert_eq!(body, "Redis rate limiting unavailable");
        assert_eq!(retry_after, None);
    }

    #[actix_web::test]
    async fn distributed_store_fail_open_degrades_to_memory() {
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                true,
            );
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, _) = full_status(transform, request).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "memory window decided"
        );
        assert_eq!(body, RATE_LIMITED_MESSAGE);
    }

    #[actix_web::test]
    async fn custom_error_responses_reach_the_banned_shapes() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_ip_banning(manager.clone(), config)
            .with_custom_error_responses(
                [(403u16, "denied:custom".to_owned())].into_iter().collect(),
            );
        manager
            .ban_ip(IpAddr::from_str("192.0.2.200").expect("ip"), 60, "operator")
            .expect("ban");
        let request = TestRequest::get()
            .uri("/hello")
            .peer_addr(peer())
            .to_srv_request();
        let (status, body, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, "denied:custom",
            "the live-ban shape takes the override"
        );
    }

    // ---------------------------------------------------------------
    // The wired stage surface: lib-binary twins of the integration
    // stage tests, so this binary's monomorphization of the fused
    // pass drives the geo/cloud/user-agent answers and the redirect
    // pass-through too.
    // ---------------------------------------------------------------

    struct UnitedStates;

    impl guard_core_engine::geo::GeoIpHandler for UnitedStates {
        fn get_country(&self, _ip: std::net::IpAddr) -> Option<String> {
            Some(String::from("US"))
        }
    }

    #[actix_web::test]
    async fn fused_geo_cloud_and_user_agent_blocks_resolve_the_answer_body() {
        let geo = guard_core_rs::geo::GeoStage::new(guard_core_rs::geo::GeoStageConfig {
            gate: guard_core_rs::geo::parse_country_lists(Vec::<String>::new(), ["US"]),
            handler: Some(std::sync::Arc::new(UnitedStates)),
            passive_mode: false,
        });
        let transform = GuardTransform::new(default_config()).with_geo_blocking(geo);
        let (status, body, _) = full_status(transform, benign_request("192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, "Forbidden",
            "the geo answer body via stage_answer_body"
        );

        let table = guard_core_rs::cloud_provider::CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
            .expect("valid ranges");
        let cloud = guard_core_rs::cloud_provider::CloudProviderStage::builder(
            guard_core_rs::cloud_provider::CloudProviderStageConfig {
                block_cloud_providers: guard_core_rs::cloud_provider::parse_cloud_selectors([
                    "AWS",
                ])
                .expect("valid selectors"),
                table,
                passive_mode: false,
            },
        )
        .build();
        let transform = GuardTransform::new(default_config()).with_cloud_provider(cloud);
        let (status, body, _) = full_status(transform, benign_request("192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "Cloud provider IP not allowed");

        let ua = guard_core_rs::user_agent::UserAgentStage::new(
            guard_core_rs::user_agent::UserAgentStageConfig {
                blocked_user_agents: guard_core_rs::user_agent::UserAgentFilter::new(["bad-bot"])
                    .expect("valid patterns"),
                ..guard_core_rs::user_agent::UserAgentStageConfig::default()
            },
        )
        .expect("valid config");
        let transform = GuardTransform::new(default_config()).with_user_agent(ua);
        let request = TestRequest::get()
            .uri("/api")
            .insert_header(("user-agent", "bad-bot/1.0"))
            .peer_addr(std::net::SocketAddr::from((
                std::net::IpAddr::from_str("192.0.2.9").expect("ip"),
                45_000,
            )))
            .to_srv_request();
        let (status, body, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");
    }

    #[actix_web::test]
    async fn fused_https_enforcement_redirects_and_passes_https_scheme() {
        let stage = guard_core_rs::https_enforcement::HttpsEnforcementStage::builder(
            guard_core_rs::https_enforcement::HttpsEnforcementStageConfig::default(),
        )
        .enforce_https(true)
        .build()
        .expect("valid");
        let guard =
            guarded(GuardTransform::new(default_config()).with_https_enforcement(stage)).await;

        // A host header with a port: the redirect target keeps the host as
        // sent; the port strip feeds the trusted-proxy comparison only.
        let request = TestRequest::get()
            .uri("/private")
            .insert_header(("host", "guard.example:8443"))
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::LOCATION)
                .expect("location")
                .to_str()
                .expect("ascii"),
            "https://guard.example:8443/private"
        );

        // A bracketed IPv6 host survives verbatim in the target.
        let request = TestRequest::get()
            .uri("/private")
            .insert_header(("host", "[2001:db8::1]:8443"))
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::LOCATION)
                .expect("location")
                .to_str()
                .expect("ascii"),
            "https://[2001:db8::1]:8443/private"
        );

        // An already-https request passes the gate untouched (the decide
        // None edge of the installed stage).
        let request = TestRequest::get()
            .uri("https://guard.example/private")
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- the unified SecurityConfig consumption (from_security_config) ---
    use crate::{
        GuardConfigError, IpBanConfigError, IpGateError, RateLimitConfigError, UserAgentConfigError,
    };
    use guard_core_engine::security_config::SecurityConfig;
    use guard_core_rs::responses::OnBlockHook;

    fn config_request(ip: &str, uri: &str) -> ServiceRequest {
        TestRequest::get()
            .uri(uri)
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str(ip).expect("test ip"),
                45_000,
            ))
            .to_srv_request()
    }

    #[actix_web::test]
    async fn the_penetration_detection_toggle_skips_the_scan() {
        // `enable_penetration_detection = false` skips the multi-surface
        // scan entirely: the attack rides through clean (200).
        let config = SecurityConfig {
            enable_penetration_detection: false,
            ..SecurityConfig::default()
        };
        let (status, _) = status_body(
            GuardTransform::from_security_config(&config).expect("valid config"),
            config_request("203.0.113.9", "/scan?q=1%20UNION%20SELECT%20password"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the toggle disables the scan");

        // The default (enabled) scans and blocks.
        let (status, _) = status_body(
            GuardTransform::from_security_config(&SecurityConfig::default()).expect("valid config"),
            config_request("203.0.113.9", "/scan?q=1%20UNION%20SELECT%20password"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    #[actix_web::test]
    async fn from_security_config_feeds_the_scan_budgets() {
        // The scan-budget knobs ride the unified config onto the scan
        // path: a two-value budget stops the scan before the third
        // value, so the threat in the last query param never surfaces.
        let config = SecurityConfig {
            detection_max_scan_values: 2,
            ..SecurityConfig::default()
        };
        let (status, _) = status_body(
            GuardTransform::from_security_config(&config).expect("valid config"),
            config_request(
                "203.0.113.9",
                "/scan?a=benign-one&b=benign-two&c=1%20UNION%20SELECT%20password",
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "values past the scan-value budget are not scanned"
        );

        // The same request under the default budget scans (the
        // below-threshold detection block, the family 400 shape).
        let (status, _) = status_body(
            GuardTransform::from_security_config(&SecurityConfig::default()).expect("valid config"),
            config_request(
                "203.0.113.9",
                "/scan?a=benign-one&b=benign-two&c=1%20UNION%20SELECT%20password",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    #[actix_web::test]
    async fn from_security_config_defaults_screen_clean_traffic() {
        let config = SecurityConfig::default();
        let (status, _) = status_body(
            GuardTransform::from_security_config(&config).expect("valid config"),
            config_request("203.0.113.9", "/hello"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn from_security_config_enforce_https_redirects_http() {
        let config = SecurityConfig {
            enforce_https: true,
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let request = TestRequest::get()
            .uri("/hello")
            .insert_header(("host", "guard.example"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("203.0.113.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (status, body, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        assert!(body.is_empty(), "the reference redirect carries no body");
    }

    #[actix_web::test]
    async fn from_security_config_emergency_mode_blocks_outside_the_whitelist() {
        let config = SecurityConfig {
            emergency_mode: true,
            emergency_whitelist: vec![String::from("198.51.100.7")],
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (blocked, _) =
            status_body(transform.clone(), config_request("203.0.113.9", "/hello")).await;
        assert_eq!(blocked, StatusCode::SERVICE_UNAVAILABLE);
        let (allowed, _) = status_body(transform, config_request("198.51.100.7", "/hello")).await;
        assert_eq!(allowed, StatusCode::OK);
    }

    #[actix_web::test]
    async fn from_security_config_blocked_user_agent_answers_the_403() {
        let config = SecurityConfig {
            blocked_user_agents: vec![String::from("bad-bot")],
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let request = TestRequest::get()
            .uri("/hello")
            .insert_header(("user-agent", "bad-bot/1.0"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("203.0.113.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (blocked, body, _) = full_status(transform, request).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");

        let (allowed, _) = status_body(
            GuardTransform::from_security_config(&config).expect("valid config"),
            config_request("203.0.113.9", "/hello"),
        )
        .await;
        assert_eq!(allowed, StatusCode::OK);
    }

    #[actix_web::test]
    async fn from_security_config_exclude_paths_bypass_the_pipeline() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            exclude_paths: vec![String::from("/docs")],
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        // An excluded path bypasses every check, gate included: the
        // blacklisted IP forwards on /docs.
        let (bypassed, _) =
            status_body(transform.clone(), config_request("203.0.113.9", "/docs")).await;
        assert_eq!(bypassed, StatusCode::OK);
        // Any other path takes the gate denial.
        let (blocked, _) = status_body(transform, config_request("203.0.113.9", "/hello")).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn from_security_config_exclude_paths_still_render_the_response_pass() {
        let config = SecurityConfig::default();
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (status, _, _) = full_status(transform, config_request("203.0.113.9", "/docs")).await;
        assert_eq!(status, StatusCode::OK);
        // The forwarded response still carries the security-header set: the
        // carve-out bypasses the request-side checks, not the response pass.
        let guard =
            guarded(GuardTransform::from_security_config(&config).expect("valid config")).await;
        let response = guard
            .call(config_request("203.0.113.9", "/docs"))
            .await
            .expect("response");
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .map(|value| value.to_str().expect("ascii")),
            Some("nosniff")
        );
    }

    #[test]
    fn from_security_config_invalid_ip_list_entry_fails_closed() {
        let config = SecurityConfig {
            whitelist: Some(vec![String::from("not-an-ip")]),
            ..SecurityConfig::default()
        };
        let error = GuardTransform::from_security_config(&config).unwrap_err();
        assert!(matches!(error, GuardConfigError::IpGate(_)));
    }

    #[actix_web::test]
    async fn from_security_config_rate_limit_crossing_answers_429() {
        let config = SecurityConfig {
            rate_limit: 1,
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (first, _, _) =
            full_status(transform.clone(), config_request("203.0.113.9", "/hello")).await;
        assert_eq!(first, StatusCode::OK);
        let (second, body, retry_after) =
            full_status(transform, config_request("203.0.113.9", "/hello")).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, crate::RATE_LIMITED_MESSAGE);
        assert_eq!(retry_after.as_deref(), Some("60"));
    }

    #[actix_web::test]
    async fn from_security_config_custom_error_responses_render() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            custom_error_responses: {
                let mut map = std::collections::BTreeMap::new();
                map.insert(403, String::from("custom-forbidden"));
                map
            },
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (status, body, _) =
            full_status(transform, config_request("203.0.113.9", "/hello")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // The custom-error body override wins over the family default.
        assert_eq!(body, "custom-forbidden");
    }

    #[actix_web::test]
    async fn from_security_config_ip_gate_denial_fires_the_on_block_hook() {
        type HookLog = Arc<Mutex<Vec<(String, Option<u16>)>>>;
        let seen: HookLog = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let hook: OnBlockHook =
            Arc::new(move |payload: &guard_core_rs::responses::BlockPayload| {
                sink.lock()
                    .expect("sink")
                    .push((payload.check_name.clone(), payload.status_code));
            });
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            on_block: Some(hook),
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (status, body, _) =
            full_status(transform, config_request("203.0.113.9", "/hello")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);
        let seen = seen.lock().expect("sink");
        assert!(
            seen.iter()
                .any(|(check, status)| check == "ip_security" && *status == Some(403)),
            "the reference on_block hook fires once with the ip_security keys: {seen:?}"
        );
    }

    #[actix_web::test]
    async fn from_security_config_ip_gate_denial_under_passive_mode_forwards() {
        let config = SecurityConfig {
            passive_mode: true,
            blacklist: vec![String::from("203.0.113.9")],
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let (status, _) = status_body(transform, config_request("203.0.113.9", "/hello")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn from_security_config_disabled_rate_limiting_forwards_freely() {
        let config = SecurityConfig {
            enable_rate_limiting: false,
            rate_limit: 1,
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        for _ in 0..3 {
            let (status, _) =
                status_body(transform.clone(), config_request("203.0.113.9", "/hello")).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[test]
    fn from_security_config_zero_rate_limit_fails_closed() {
        let config = SecurityConfig {
            rate_limit: 0,
            ..SecurityConfig::default()
        };
        let error = GuardTransform::from_security_config(&config).unwrap_err();
        assert!(matches!(error, GuardConfigError::RateLimit(_)));
    }

    #[actix_web::test]
    async fn from_security_config_detection_exclusions_and_categories_reach_the_scan() {
        let config = SecurityConfig {
            enabled_detection_categories: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("xss"));
                set
            },
            excluded_detection_params: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("q"));
                set
            },
            detection_scan_body: false,
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        // The sqli category is disabled by the enabled-categories override:
        // the sqli probe forwards.
        let (status, _) = status_body(
            transform,
            config_request("203.0.113.9", "/hello?q=1%27+OR+1%3D1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn from_security_config_security_headers_and_cors_render() {
        let config = SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec![String::from("https://app.test")],
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        let guard = guarded(transform).await;
        let request = TestRequest::get()
            .uri("/hello")
            .insert_header(("origin", "https://app.test"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("203.0.113.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let response = guard.call(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .map(|value| value.to_str().expect("ascii")),
            Some("nosniff")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .map(|value| value.to_str().expect("ascii")),
            Some("https://app.test")
        );
    }

    #[test]
    fn from_security_config_empty_category_set_skips_the_exclusion_block() {
        // The reference's empty `enabled_detection_categories` frozenset:
        // an explicitly empty set disables every category, and the
        // detection-exclusion block is not installed at all.
        let config = SecurityConfig {
            enabled_detection_categories: std::collections::BTreeSet::new(),
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        assert!(transform.detection_exclusions().is_none());
    }

    #[test]
    fn from_security_config_silent_observability_skips_the_knob() {
        let config = SecurityConfig {
            log_suspicious_level: None,
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        assert!(transform.observability().is_none());
    }

    #[test]
    fn from_security_config_disabled_security_headers_skip_the_processor() {
        let config = SecurityConfig {
            security_headers: guard_core_engine::security_headers::SecurityHeadersConfig {
                enabled: false,
                ..guard_core_engine::security_headers::SecurityHeadersConfig::reference_default()
            },
            ..SecurityConfig::default()
        };
        let transform = GuardTransform::from_security_config(&config).expect("valid config");
        assert!(transform.response_processor.as_ref().is_none());
    }

    #[test]
    fn guard_config_error_display_and_source_cover_every_variant() {
        let ip_gate: GuardConfigError = IpGateError {
            list: "whitelist",
            entry: String::from("nope"),
        }
        .into();
        assert!(ip_gate.to_string().contains("ip list"));
        assert!(std::error::Error::source(&ip_gate).is_some());

        let rate_limit: GuardConfigError = RateLimitConfigError {
            field: std::borrow::Cow::Borrowed("rate_limit"),
            reason: "must be at least 1",
        }
        .into();
        assert!(rate_limit.to_string().contains("rate limit"));
        assert!(std::error::Error::source(&rate_limit).is_some());

        let user_agent: GuardConfigError = UserAgentConfigError {
            entry: String::from("bad-bot"),
            reason: String::from("rejected"),
        }
        .into();
        assert!(user_agent.to_string().contains("blocked user agent"));
        assert!(std::error::Error::source(&user_agent).is_some());

        let ban: GuardConfigError = IpBanConfigError::NonPositive {
            field: "auto_ban_threshold",
        }
        .into();
        assert!(ban.to_string().contains("ip ban"));
        assert!(std::error::Error::source(&ban).is_some());
    }

    #[test]
    fn map_log_level_covers_every_reference_level() {
        assert!(matches!(
            crate::map_log_level(guard_core_engine::security_config::LogLevel::Info),
            guard_core_rs::logging::LogLevel::Info
        ));
        assert!(matches!(
            crate::map_log_level(guard_core_engine::security_config::LogLevel::Debug),
            guard_core_rs::logging::LogLevel::Debug
        ));
        assert!(matches!(
            crate::map_log_level(guard_core_engine::security_config::LogLevel::Warning),
            guard_core_rs::logging::LogLevel::Warning
        ));
        assert!(matches!(
            crate::map_log_level(guard_core_engine::security_config::LogLevel::Error),
            guard_core_rs::logging::LogLevel::Error
        ));
        assert!(matches!(
            crate::map_log_level(guard_core_engine::security_config::LogLevel::Critical),
            guard_core_rs::logging::LogLevel::Critical
        ));
    }

    // --- the reference RouteConfig carrier consumption (GAP-R2) ---

    use crate::RouteConfig;
    use guard_core_engine::route_config::RouteConfigResolver;

    fn resolver_for(paths: &[(&str, &str)], config: RouteConfig) -> RouteConfigResolver {
        let owned: Vec<(String, String)> = paths
            .iter()
            .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
            .collect();
        Arc::new(move |method, path| {
            owned
                .iter()
                .any(|(route_method, route_path)| route_method == method && route_path == path)
                .then(|| Arc::new(config.clone()))
        })
    }

    fn carrier_request(method: &str, uri: &str, ip: &str) -> ServiceRequest {
        TestRequest::default()
            .method(actix_web::http::Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(uri)
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str(ip).expect("test ip"),
                45_000,
            ))
            .to_srv_request()
    }

    #[actix_web::test]
    async fn the_penetration_bypass_skips_the_scan_for_its_path_only() {
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("penetration"));
                set
            },
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/open")], config));
        let (open, _) = status_body(
            transform.clone(),
            carrier_request("GET", "/open?q=1%27+OR+1%3D1", "192.0.2.9"),
        )
        .await;
        assert_eq!(open, StatusCode::OK);
        let (blocked, _) = status_body(
            transform,
            carrier_request("GET", "/locked?q=1%27+OR+1%3D1", "192.0.2.9"),
        )
        .await;
        assert_eq!(blocked, StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn route_require_https_forces_the_redirect() {
        let config = RouteConfig {
            require_https: true,
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/tls")], config));
        let request = TestRequest::get()
            .uri("/tls")
            .insert_header(("host", "guard.example"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("192.0.2.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (status, _, _) = full_status(transform, request).await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
    }

    #[actix_web::test]
    async fn the_route_rate_view_becomes_the_tier() {
        let config = RouteConfig {
            rate_limit: Some(1),
            rate_limit_window: Some(60),
            ..RouteConfig::default()
        };
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1000,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter)
            .with_route_configs(resolver_for(&[("GET", "/login")], config));
        let (first, _, _) = full_status(
            transform.clone(),
            carrier_request("GET", "/login", "192.0.2.9"),
        )
        .await;
        assert_eq!(first, StatusCode::OK);
        let (second, _, retry_after) =
            full_status(transform, carrier_request("GET", "/login", "192.0.2.9")).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after.as_deref(), Some("60"));
    }

    #[actix_web::test]
    async fn the_carrier_extension_wins_over_the_resolver() {
        let config = RouteConfig {
            rate_limit: Some(1),
            rate_limit_window: Some(60),
            ..RouteConfig::default()
        };
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1000,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let transform = GuardTransform::new(default_config())
            .with_rate_limiting(limiter)
            .with_route_configs(resolver_for(&[("GET", "/login")], config));
        let request = with_ext(
            carrier_request("GET", "/login", "192.0.2.9"),
            Arc::new(RouteConfig::default()),
        );
        let (first, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(first, StatusCode::OK);
        let (second, _, _) =
            full_status(transform, carrier_request("GET", "/login", "192.0.2.9")).await;
        assert_eq!(second, StatusCode::OK);
    }

    #[actix_web::test]
    async fn route_blocked_user_agents_answer_the_403() {
        let config = RouteConfig {
            blocked_user_agents: vec![String::from("route-bot")],
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/api")], config));
        let request = TestRequest::get()
            .uri("/api")
            .insert_header(("user-agent", "route-bot/2.0"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("192.0.2.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (blocked, body, _) = full_status(transform, request).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");
    }

    #[actix_web::test]
    async fn an_invalid_carrier_tier_fails_secure() {
        let config = RouteConfig {
            rate_limit: Some(0),
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/bad")], config));
        let (status, _, _) =
            full_status(transform, carrier_request("GET", "/bad", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn the_ip_bypass_skips_the_gate_for_its_route() {
        let gate = crate::IpGateConfig::new([] as [&str; 0], ["192.0.2.9"], [] as [&str; 0])
            .expect("valid lists");
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("ip"));
                set
            },
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_ip_gate(gate)
            .with_route_configs(resolver_for(&[("GET", "/open")], config));
        let (open, _) = status_body(
            transform.clone(),
            carrier_request("GET", "/open", "192.0.2.9"),
        )
        .await;
        assert_eq!(open, StatusCode::OK);
        let (blocked, _) =
            status_body(transform, carrier_request("GET", "/locked", "192.0.2.9")).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn a_non_compilable_route_pattern_fails_secure() {
        let config = RouteConfig {
            blocked_user_agents: vec![String::from("([")],
            ..RouteConfig::default()
        };
        let transform = GuardTransform::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/api")], config));
        let (status, body, _) =
            full_status(transform, carrier_request("GET", "/api", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, crate::FAILURE_MESSAGE);
    }

    #[actix_web::test]
    async fn route_require_https_rides_the_installed_stage_lane() {
        let config = RouteConfig {
            require_https: true,
            ..RouteConfig::default()
        };
        let stage = guard_core_rs::https_enforcement::HttpsEnforcementStage::builder(
            guard_core_rs::https_enforcement::HttpsEnforcementStageConfig::default(),
        )
        .build()
        .expect("valid stage");
        let transform = GuardTransform::new(default_config())
            .with_https_enforcement(stage)
            .with_route_configs(resolver_for(&[("GET", "/tls")], config));
        let request = TestRequest::get()
            .uri("/tls")
            .insert_header(("host", "guard.example"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("192.0.2.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (status, _, _) = full_status(transform.clone(), request).await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        // An unlisted path passes (the global arm is off and the stage's
        // resolver seam is not installed).
        let request = TestRequest::get()
            .uri("/other")
            .insert_header(("host", "guard.example"))
            .peer_addr(std::net::SocketAddr::new(
                IpAddr::from_str("192.0.2.9").expect("test ip"),
                45_000,
            ))
            .to_srv_request();
        let (plain, _, _) = full_status(transform, request).await;
        assert_eq!(plain, StatusCode::OK);
    }
}
