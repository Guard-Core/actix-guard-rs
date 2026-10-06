//! End-to-end behavior of the public API: `GuardTransform` wrapping real
//! services, exercised with the actix Web test utilities.

use actix_guard_rs::{BLOCKED_MESSAGE, GuardTransform, OVERSIZE_MESSAGE, default_config};
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_TYPE, LOCATION};
use actix_web::test::{TestRequest, call_service, init_service, read_body};
use actix_web::{App, Error, HttpRequest, HttpResponse, web};
use bytes::Bytes;
use std::future::Ready;
use std::io;
use std::task::{Context, Poll};

/// An echo handler: answers `method path x-custom body`, so tests can assert
/// that the guard forwards the request untouched.
async fn echo(request: HttpRequest, body: Bytes) -> HttpResponse {
    let custom = request
        .headers()
        .get("x-custom")
        .map(|value| value.to_str().expect("ascii").to_owned())
        .unwrap_or_default();
    HttpResponse::Ok().body(format!(
        "{} {} {custom} {}",
        request.method(),
        request.path(),
        String::from_utf8_lossy(&body)
    ))
}

async fn body_text<B>(response: ServiceResponse<B>) -> String
where
    B: MessageBody,
{
    String::from_utf8_lossy(&read_body(response).await).into_owned()
}

fn get(path: &str) -> ServiceRequest {
    TestRequest::get().uri(path).to_srv_request()
}

fn post(path: &str, body: &str) -> ServiceRequest {
    TestRequest::post()
        .uri(path)
        .insert_header(("content-type", "application/json"))
        .set_payload(body.to_owned())
        .to_srv_request()
}

#[actix_web::test]
async fn benign_request_passes_through_untouched() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items?limit=5")
        .insert_header(("x-custom", "hello"))
        .set_payload(r#"{"name":"renn"}"#)
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        r#"POST /api/items hello {"name":"renn"}"#
    );
}

#[actix_web::test]
async fn xss_payload_in_body_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/comment")
        .set_payload("<script>alert(1)</script>")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[actix_web::test]
async fn traversal_payload_in_path_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/files/../../etc/passwd")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[actix_web::test]
async fn command_injection_in_query_is_blocked() {
    // Raw spaces are invalid in a URI, so the payload travels percent-encoded
    // and the engine's preprocessor decodes it back to `$(echo id)`.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/search?cmd=$(echo%20id)")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("x-comment", "<script>alert(1)</script>"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn excluded_headers_are_never_scanned() {
    // `User-Agent` is on the exclusion list, so even a value that looks like a
    // payload is not fed to the engine. This pins the documented policy.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("user-agent", "<script>alert(1)</script>"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()).with_body_cap(16))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items")
        .set_payload("this body is much longer than sixteen bytes")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[actix_web::test]
async fn body_under_the_cap_is_forwarded_intact() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()).with_body_cap(16))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items")
        .set_payload("short but valid")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items  short but valid"
    );
}

#[actix_web::test]
async fn custom_header_name_is_case_insensitive_on_the_exclusion_list() {
    // `HeaderMap` normalizes names to lowercase; scanning decisions must not
    // depend on the casing the client sent.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("X-Custom", "benign value"))
        .insert_header(("user-agent", "actix-guard-tests/0.1"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn concurrent_requests_are_screened_independently() {
    let guard = GuardTransform::new(default_config())
        .new_transform(EchoService)
        .await
        .expect("transform");

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let guard = guard.clone();
            let request = if index % 2 == 0 {
                get("/health")
            } else {
                post("/api/comment", "<script>alert(1)</script>")
            };
            actix_web::rt::spawn(
                async move { guard.call(request).await.expect("response").status() },
            )
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::OK, "benign request {index}");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "threat request {index}");
        }
    }
}

#[actix_web::test]
async fn inner_service_errors_are_propagated_not_swallowed() {
    let guard = GuardTransform::new(default_config())
        .new_transform(ErrorService)
        .await
        .expect("transform");

    let error = guard
        .call(get("/health"))
        .await
        .expect_err("inner error must propagate");
    assert!(error.to_string().contains("upstream down"));
}

#[actix_web::test]
async fn poll_ready_forwards_to_the_inner_service() {
    let guard = GuardTransform::new(default_config())
        .new_transform(EchoService)
        .await
        .expect("transform");
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Service::poll_ready(&guard, &mut cx) {
        Poll::Ready(result) => result.expect("ready"),
        Poll::Pending => panic!("echo service is always ready"),
    }
}

/// A minimal inner service for direct construction: always answers `200` with
/// an empty body and never inspects the request.
#[derive(Clone)]
struct EchoService;

impl Service<ServiceRequest> for EchoService {
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<ServiceResponse, Error>>;

    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        std::future::ready(Ok(request.into_response(HttpResponse::Ok().finish())))
    }
}

/// An inner service that always fails, to prove the guard does not swallow
/// upstream errors.
#[derive(Clone)]
struct ErrorService;

impl Service<ServiceRequest> for ErrorService {
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<ServiceResponse, Error>>;

    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, _request: ServiceRequest) -> Self::Future {
        std::future::ready(Err(Error::from(io::Error::other("upstream down"))))
    }
}

// --- the newly wired stage surface (the reference pipeline checks) ---

/// An inner service that always answers `404` (the return-rule surface).
#[derive(Clone)]
struct NotFoundService;

impl Service<ServiceRequest> for NotFoundService {
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<ServiceResponse, Error>>;

    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        std::future::ready(Ok(request.into_response(HttpResponse::NotFound().finish())))
    }
}

use actix_guard_rs::{
    CloudProviderStage, CustomChecksStage, EmergencyModeStage, GeoStage, GuardService,
    HeadersAuthStage, HttpsEnforcementStage, IpBanConfig, IpBanManager, ReferrerStage,
    ResponseProcessor, RouteGuard, SecurityHeadersConfig, TimeWindowStage, UserAgentStage,
    UserAgentStageConfig,
};
use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::cors::CorsConfig;
use guard_core_engine::custom_checks::{
    CustomRequestContext as ActixValidatorContext, CustomResponse,
    CustomValidatorFn as ActixValidatorFn, ValidatorAnswer,
};
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::geo::parse_country_lists;
use guard_core_engine::headers_auth::{HeaderAuthRules, REQUIRED_SENTINEL, RequiredHeader};
use guard_core_engine::ip_ban::ThreatBanEntry;
use guard_core_rs::cloud_provider::{
    CloudIpTable, CloudProviderStageConfig, parse_cloud_selectors,
};
use guard_core_rs::geo::GeoStageConfig;
use guard_core_rs::https_enforcement::HttpsEnforcementStageConfig;
use guard_core_rs::route_gates::GateConfig;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

/// A GET request attributed to `ip` (the peer address the guard reads).
fn attributed_get(path: &str, ip: &str) -> ServiceRequest {
    TestRequest::get()
        .uri(path)
        .peer_addr(SocketAddr::from((
            IpAddr::from_str(ip).expect("test ip"),
            45_000,
        )))
        .to_srv_request()
}

async fn status_of<S>(guard: &GuardService<S>, request: ServiceRequest) -> (StatusCode, String)
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    let response = guard.call(request).await.expect("response");
    let status = response.status();
    let body = body_text(response).await;
    (status, body)
}

#[actix_web::test]
async fn emergency_mode_blocks_outside_the_whitelist_and_fails_secure_without_an_ip() {
    let stage = EmergencyModeStage::builder(
        guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
    )
    .emergency_mode(true)
    .emergency_whitelist(["203.0.113.9"])
    .build()
    .expect("valid whitelist");
    let guard = GuardTransform::new(default_config())
        .with_emergency_mode(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, body) = status_of(&guard, get("/api")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "Service temporarily unavailable");

    let (status, _) = status_of(&guard, attributed_get("/api", "203.0.113.9")).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn https_enforcement_redirects_plain_http() {
    let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
        .enforce_https(true)
        .build()
        .expect("valid");
    let guard = GuardTransform::new(default_config())
        .with_https_enforcement(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let request = TestRequest::get()
        .uri("/private?token=1")
        .insert_header(("host", "guard.example"))
        .to_srv_request();
    let response = guard.call(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        "https://guard.example/private?token=1"
    );
}

#[actix_web::test]
async fn required_headers_and_authentication_answer_the_reference_shapes() {
    let stage = HeadersAuthStage::new(
        None,
        Arc::new(|path: &str| {
            (path == "/private").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: String::from("x-api-key"),
                            expected: String::from(REQUIRED_SENTINEL),
                        }],
                        auth_required: Some(String::from("bearer")),
                        ..HeaderAuthRules::default()
                    },
                    verifier: Some(Arc::new(|credential: &str| credential == "let-me-in")),
                    api_key_verifier: None,
                })
            })
        }),
    );
    let guard = GuardTransform::new(default_config())
        .with_headers_auth(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, _) = status_of(&guard, get("/private")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let request = TestRequest::get()
        .uri("/private")
        .insert_header(("x-api-key", "present"))
        .insert_header(("authorization", "Bearer nope"))
        .to_srv_request();
    let (status, body) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "Authentication required");

    let request = TestRequest::get()
        .uri("/private")
        .insert_header(("x-api-key", "present"))
        .insert_header(("authorization", "Bearer let-me-in"))
        .to_srv_request();
    let (status, _) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn referrer_gate_blocks_a_missing_or_foreign_referrer() {
    let stage = ReferrerStage::builder(GateConfig::default())
        .resolver(Arc::new(|path: &str| {
            (path == "/gated").then(|| vec![String::from("https://good.example")])
        }))
        .build();
    let guard = GuardTransform::new(default_config())
        .with_referrer_gate(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, body) = status_of(&guard, get("/gated")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Referrer required");

    let request = TestRequest::get()
        .uri("/gated")
        .insert_header(("referer", "https://good.example/page"))
        .to_srv_request();
    let (status, _) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::OK);

    let request = TestRequest::get()
        .uri("/gated")
        .insert_header(("referer", "https://evil.example/page"))
        .to_srv_request();
    let (status, body) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Invalid referrer");
}

#[actix_web::test]
async fn custom_validators_block_with_the_validator_response() {
    let stage = CustomChecksStage::builder()
        .validators_resolver(Arc::new(|path: &str| {
            (path == "/private").then(|| {
                vec![(
                    String::from("post_only"),
                    Arc::new(|ctx: &ActixValidatorContext<'_>| {
                        (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                            CustomResponse { status: Some(403) },
                        ))
                    }) as ActixValidatorFn,
                )]
            })
        }))
        .build();
    let guard = GuardTransform::new(default_config())
        .with_custom_checks(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, _) = status_of(&guard, get("/private")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = status_of(&guard, post("/private", "{}")).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn time_window_gate_blocks_outside_the_window() {
    // The window is computed from the live clock so the test is
    // deterministic: the gate closes for everything except a two-minute
    // band that starts two minutes from now.
    let now = chrono::Utc::now();
    let start = (now + chrono::Duration::minutes(2))
        .format("%H:%M")
        .to_string();
    let end = (now + chrono::Duration::minutes(3))
        .format("%H:%M")
        .to_string();
    let stage = TimeWindowStage::builder(GateConfig::default())
        .resolver(Arc::new(move |path: &str| {
            (path == "/nightly").then(|| guard_core_engine::time_window::TimeWindow {
                start: Some(start.clone()),
                end: Some(end.clone()),
                timezone: Some(String::from("UTC")),
            })
        }))
        .build();
    let guard = GuardTransform::new(default_config())
        .with_time_window_gate(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, body) = status_of(&guard, get("/nightly")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Access not allowed at this time");

    let (status, _) = status_of(&guard, get("/open")).await;
    assert_eq!(status, StatusCode::OK);
}

/// A hand-written resolver: every address resolves to `US`.
struct UnitedStates;

impl GeoIpHandler for UnitedStates {
    fn get_country(&self, _ip: std::net::IpAddr) -> Option<String> {
        Some(String::from("US"))
    }
}

#[actix_web::test]
async fn geo_country_blocking_answers_the_reference_403() {
    let stage = GeoStage::new(GeoStageConfig {
        gate: parse_country_lists(Vec::<String>::new(), ["US"]),
        handler: Some(Arc::new(UnitedStates)),
        passive_mode: false,
    });
    let guard = GuardTransform::new(default_config())
        .with_geo_blocking(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, body) = status_of(&guard, attributed_get("/api", "192.0.2.9")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Forbidden");
}

#[actix_web::test]
async fn cloud_provider_blocking_answers_the_reference_403() {
    let table = CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
        .expect("valid ranges");
    let stage = CloudProviderStage::new(CloudProviderStageConfig {
        block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
        table,
        passive_mode: false,
    });
    let guard = GuardTransform::new(default_config())
        .with_cloud_provider(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, body) = status_of(&guard, attributed_get("/api", "192.0.2.9")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Cloud provider IP not allowed");

    let (status, _) = status_of(&guard, attributed_get("/api", "198.51.100.9")).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn user_agent_blocking_answers_the_reference_403() {
    let stage = UserAgentStage::new(UserAgentStageConfig {
        blocked_user_agents: guard_core_rs::user_agent::UserAgentFilter::new(["bad-bot"])
            .expect("valid patterns"),
        ..UserAgentStageConfig::default()
    })
    .expect("valid config");
    let guard = GuardTransform::new(default_config())
        .with_user_agent(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let request = TestRequest::get()
        .uri("/api")
        .insert_header(("user-agent", "bad-bot/1.0"))
        .to_srv_request();
    let (status, body) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "User-Agent not allowed");

    let request = TestRequest::get()
        .uri("/api")
        .insert_header(("user-agent", "friendly-crawler/2.0"))
        .to_srv_request();
    let (status, _) = status_of(&guard, request).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn custom_request_blocks_with_the_function_response() {
    let stage = CustomChecksStage::builder()
        .custom_request(
            "maintenance_gate",
            Arc::new(|ctx| (ctx.path == "/admin").then_some(CustomResponse { status: Some(503) })),
        )
        .build();
    let guard = GuardTransform::new(default_config())
        .with_custom_checks(stage)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let (status, _) = status_of(&guard, get("/admin")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = status_of(&guard, get("/public")).await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_web::test]
async fn response_processor_renders_security_headers_and_cors_on_every_response() {
    let processor = ResponseProcessor::new(
        Some(SecurityHeadersConfig::reference_default()),
        Some(CorsConfig {
            enabled: true,
            allow_origins: vec![String::from("https://app.example.com")],
            ..CorsConfig::default()
        }),
        Vec::new(),
        Arc::new(Mutex::new(
            guard_core_engine::behavior::BehaviorTracker::new(),
        )),
        IpBanManager::new(),
        true,
        262_144,
        false,
    );
    let guard = GuardTransform::new(default_config())
        .with_response_processor(processor)
        .new_transform(EchoService)
        .await
        .expect("transform");

    let request = TestRequest::get()
        .uri("/api")
        .insert_header(("origin", "https://app.example.com"))
        .to_srv_request();
    let response = guard.call(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .expect("nosniff"),
        "nosniff"
    );
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("cors"),
        "https://app.example.com"
    );

    // Block answers carry the set too (headers on blocked + passthrough).
    let response = guard
        .call(post("/api/comment", "<script>alert(1)</script>"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-frame-options").expect("frame"),
        "SAMEORIGIN"
    );
}

#[actix_web::test]
async fn a_return_pattern_rule_bans_at_the_threshold_through_the_fused_pipeline() {
    // The processor's return rules share the transform's ban store: a
    // crossed `status:404` ban rule answers the next request with the
    // bans arm's 403 ("IP address banned"), the reference's
    // behavioral-violation path.
    let bans = IpBanManager::new();
    let processor = ResponseProcessor::new(
        None,
        None,
        vec![BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 2,
            window: 3600,
            pattern: String::from("status:404"),
            action: String::from("ban"),
            ban_duration: Some(900),
            correlate_with_detection: false,
        }],
        Arc::new(Mutex::new(
            guard_core_engine::behavior::BehaviorTracker::new(),
        )),
        bans.clone(),
        true,
        262_144,
        false,
    );
    // The inner service answers 404: the return-rule surface the test
    // drives.
    let guard = GuardTransform::new(default_config())
        .with_ip_banning(
            bans.clone(),
            IpBanConfig::new(true, 10, 3600, Vec::<(String, ThreatBanEntry)>::new())
                .expect("valid"),
        )
        .with_response_processor(processor)
        .new_transform(NotFoundService)
        .await
        .expect("transform");

    // Two 404s track; the third trips the rule and bans the IP.
    for _ in 0..3 {
        let response = guard
            .call(attributed_get("/missing", "192.0.2.41"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert!(
        bans.is_banned(IpAddr::from_str("192.0.2.41").expect("ip")),
        "the ban landed in the shared store"
    );

    // The next request answers from the bans arm.
    let (status, body) = status_of(&guard, attributed_get("/missing", "192.0.2.41")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "IP address banned");
}
