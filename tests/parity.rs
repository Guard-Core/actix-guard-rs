//! Reference-parity behavior of the public API: the scoped `exclude_paths`
//! semantics, client resolution, the `from_security_config` consumption, and
//! the response pass. Every test drives a real actix `App` through the
//! public surface only.

use actix_guard_rs::{GuardTransform, IpBanConfig, IpBanManager, default_config};
use actix_web::body::MessageBody;
use actix_web::dev::ServiceResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::HeaderMap;
use actix_web::test::{TestRequest, call_service, init_service, read_body};
use actix_web::{App, HttpResponse, web};
use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::route_config::RouteConfig;
use guard_core_engine::security_config::SecurityConfig;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

const ATTACK_QUERY: &str = "q=%3Cscript%3Ealert(1)%3C/script%3E";

struct Out {
    status: StatusCode,
    body: String,
    headers: HeaderMap,
}

async fn out<B: MessageBody>(response: ServiceResponse<B>) -> Out {
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8_lossy(&read_body(response).await).into_owned();
    Out {
        status,
        body,
        headers,
    }
}

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

macro_rules! serve {
    ($transform:expr) => {
        init_service(
            App::new()
                .wrap($transform)
                .default_service(web::to(ok_handler)),
        )
        .await
    };
    ($transform:expr, $handler:expr) => {
        init_service(
            App::new()
                .wrap($transform)
                .default_service(web::to($handler)),
        )
        .await
    };
}

macro_rules! hit {
    ($svc:expr, $request:expr) => {
        out(call_service(&$svc, $request.to_request()).await).await
    };
}

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().expect("test ip"), 45_000)
}

fn get(ip: &str, uri: &str) -> TestRequest {
    TestRequest::get().uri(uri).peer_addr(peer(ip))
}

fn from_config(config: &SecurityConfig) -> GuardTransform {
    GuardTransform::from_security_config(config).expect("valid config")
}

fn header(out: &Out, name: &str) -> Option<String> {
    out.headers
        .get(name)
        .map(|value| value.to_str().expect("ascii header").to_owned())
}

struct FixedCountry(&'static str);

impl GeoIpHandler for FixedCountry {
    fn get_country(&self, _ip: IpAddr) -> Option<String> {
        Some(self.0.to_owned())
    }
}

fn return_rule(pattern: &str, threshold: u32) -> BehaviorRule {
    BehaviorRule {
        rule_type: "return_pattern".to_owned(),
        threshold,
        window: 60,
        pattern: pattern.to_owned(),
        action: "ban".to_owned(),
        ban_duration: Some(60),
        correlate_with_detection: false,
    }
}

// --- exclude_paths: the reference matcher, scoped not bypassed ---

#[actix_web::test]
async fn the_default_static_exclusion_covers_nested_assets_on_a_segment_boundary() {
    let svc = serve!(from_config(&SecurityConfig::default()));
    let nested = hit!(
        svc,
        get("203.0.113.9", &format!("/static/app.js?{ATTACK_QUERY}"))
    );
    assert_eq!(
        nested.status,
        StatusCode::OK,
        "/static covers /static/app.js"
    );
    let sibling = hit!(
        svc,
        get("203.0.113.9", &format!("/staticx/app.js?{ATTACK_QUERY}"))
    );
    assert_eq!(
        sibling.status,
        StatusCode::BAD_REQUEST,
        "/staticx is not under /static"
    );
}

#[actix_web::test]
async fn an_encoded_traversal_out_of_an_excluded_prefix_is_not_excluded() {
    let svc = serve!(from_config(&SecurityConfig::default()));
    let escaped = hit!(
        svc,
        get(
            "203.0.113.9",
            &format!("/static/%2e%2e/private?{ATTACK_QUERY}")
        )
    );
    assert_eq!(escaped.status, StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn an_excluded_path_still_answers_a_live_ban() {
    let manager = IpBanManager::new();
    manager
        .ban_ip("203.0.113.9".parse().expect("ip"), 600, "test ban")
        .expect("ban");
    let transform = GuardTransform::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_ip_banning(
            manager,
            IpBanConfig::new(
                true,
                5,
                3600,
                Vec::<(String, actix_guard_rs::ThreatBanEntry)>::new(),
            )
            .expect("valid config"),
        );
    let svc = serve!(transform);
    let banned = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
    assert_eq!(banned.body, actix_guard_rs::BANNED_MESSAGE);
    let other = hit!(svc, get("203.0.113.10", "/docs"));
    assert_eq!(other.status, StatusCode::OK);
}

#[actix_web::test]
async fn an_excluded_path_still_enforces_the_global_ip_lists() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let blocked = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.body, actix_guard_rs::FORBIDDEN_MESSAGE);
    let allowed = hit!(svc, get("203.0.113.10", "/docs"));
    assert_eq!(allowed.status, StatusCode::OK);
}

#[actix_web::test]
async fn an_excluded_path_still_hits_the_rate_limit() {
    let config = SecurityConfig {
        rate_limit: 2,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    for _ in 0..2 {
        let passed = hit!(svc, get("203.0.113.9", "/docs"));
        assert_eq!(passed.status, StatusCode::OK);
    }
    let limited = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&limited, "retry-after").as_deref(), Some("60"));
}

#[actix_web::test]
async fn an_excluded_path_still_applies_the_global_country_rules() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("US"))),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let blocked = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn an_excluded_path_ignores_the_route_ip_restrictions() {
    let transform = GuardTransform::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(RouteConfig {
                ip_blacklist: Some(vec!["203.0.113.9".to_owned()]),
                ..RouteConfig::default()
            }))
        }));
    let svc = serve!(transform);
    let excluded = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(excluded.status, StatusCode::OK, "route lists do not apply");
    let guarded = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(guarded.status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn an_excluded_path_skips_https_enforcement() {
    let config = SecurityConfig {
        enforce_https: true,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let excluded = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(excluded.status, StatusCode::OK);
    let other = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(other.status, StatusCode::MOVED_PERMANENTLY);
}

#[actix_web::test]
async fn an_excluded_response_still_gets_the_security_headers() {
    let svc = serve!(from_config(&SecurityConfig::default()));
    let excluded = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(excluded.status, StatusCode::OK);
    assert_eq!(
        header(&excluded, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
}

#[actix_web::test]
async fn an_excluded_response_emits_the_request_metrics() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let collector = guard_core_rs::metrics::MetricsCollector::new(true).with_handler(Arc::new(
        move |metric: &guard_core_rs::metrics::SecurityMetric| {
            sink.lock().expect("sink").push(metric.metric_type.clone());
        },
    ));
    let svc = serve!(from_config(&SecurityConfig::default()).with_metrics(collector));
    let excluded = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(excluded.status, StatusCode::OK);
    let recorded = seen.lock().expect("sink").clone();
    assert!(
        recorded.iter().any(|kind| kind == "request_count"),
        "the excluded request is counted: {recorded:?}"
    );
}

#[actix_web::test]
async fn an_excluded_request_does_not_feed_the_return_rules() {
    // A rule trips once its count exceeds the threshold (2): the third
    // tracked response trips it and the fourth request is banned.
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("status:200", 2)],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    // The excluded request is withheld from the behavioral tracker: were it
    // counted, the rule would trip one request earlier.
    let excluded = hit!(svc, get("203.0.113.9", "/docs"));
    assert_eq!(excluded.status, StatusCode::OK);
    for _ in 0..3 {
        let tracked = hit!(svc, get("203.0.113.9", "/api"));
        assert_eq!(
            tracked.status,
            StatusCode::OK,
            "the excluded hit did not count toward the rule"
        );
    }
    let banned = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
}

// --- client resolution ---

#[actix_web::test]
async fn a_missing_client_address_is_rejected_under_fail_secure() {
    let svc = serve!(from_config(&SecurityConfig::default()));
    let rejected = hit!(svc, TestRequest::get().uri("/api"));
    assert_eq!(rejected.status, StatusCode::FORBIDDEN);
    assert_eq!(rejected.body, "Client address could not be determined");
    assert_eq!(
        header(&rejected, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "the rejection rides the response pass"
    );
}

#[actix_web::test]
async fn the_unresolved_client_rejection_fires_the_block_hook() {
    let seen: Arc<Mutex<Vec<guard_core_engine::payload::BlockPayload>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let config = SecurityConfig {
        on_block: Some(Arc::new(move |payload| {
            sink.lock().expect("sink").push(payload.clone());
        })),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let rejected = hit!(svc, TestRequest::get().uri("/api"));
    assert_eq!(rejected.status, StatusCode::FORBIDDEN);
    let payloads = seen.lock().expect("sink").clone();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].check_name, "client_address_unresolved");
    assert_eq!(payloads[0].reason, "Client address could not be determined");
    assert_eq!(payloads[0].status_code, Some(403));
}

#[actix_web::test]
async fn a_missing_client_address_continues_unattributed_without_fail_secure() {
    let config = SecurityConfig {
        fail_secure: false,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let passed = hit!(svc, TestRequest::get().uri("/api"));
    assert_eq!(passed.status, StatusCode::OK);
}

#[actix_web::test]
async fn a_bare_layer_without_a_peer_keeps_passing() {
    let svc = serve!(GuardTransform::new(default_config()));
    let passed = hit!(svc, TestRequest::get().uri("/api"));
    assert_eq!(passed.status, StatusCode::OK);
}

#[actix_web::test]
async fn an_excluded_path_without_a_peer_continues_scoped() {
    let svc = serve!(from_config(&SecurityConfig::default()));
    let excluded = hit!(svc, TestRequest::get().uri("/static/app.js"));
    assert_eq!(excluded.status, StatusCode::OK);
    let rejected = hit!(svc, TestRequest::get().uri("/api"));
    assert_eq!(rejected.status, StatusCode::FORBIDDEN);
}

fn behind_a_proxy() -> SecurityConfig {
    SecurityConfig {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        blacklist: vec!["203.0.113.7".to_owned()],
        ..SecurityConfig::default()
    }
}

#[actix_web::test]
async fn a_trusted_proxy_forwards_the_real_client_identity() {
    let svc = serve!(from_config(&behind_a_proxy()));
    let blocked = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-for", "203.0.113.7"))
    );
    assert_eq!(
        blocked.status,
        StatusCode::FORBIDDEN,
        "the forwarded client is the identity the gate sees"
    );
    let allowed = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-for", "198.51.100.4"))
    );
    assert_eq!(allowed.status, StatusCode::OK);
}

#[actix_web::test]
async fn an_untrusted_peer_cannot_spoof_the_forwarded_identity() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..behind_a_proxy()
    };
    let svc = serve!(from_config(&config));
    // The peer is not a trusted proxy: its own address is the identity,
    // whatever X-Forwarded-For claims.
    let spoofed = hit!(
        svc,
        get("203.0.113.9", "/api").insert_header(("x-forwarded-for", "198.51.100.4"))
    );
    assert_eq!(spoofed.status, StatusCode::FORBIDDEN);
    let innocent = hit!(
        svc,
        get("198.51.100.99", "/api").insert_header(("x-forwarded-for", "203.0.113.7"))
    );
    assert_eq!(innocent.status, StatusCode::OK);
}

#[actix_web::test]
async fn the_rate_limit_keys_on_the_forwarded_client_not_the_proxy() {
    let config = SecurityConfig {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        rate_limit: 1,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let first = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-for", "198.51.100.4"))
    );
    assert_eq!(first.status, StatusCode::OK);
    let other_client = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-for", "198.51.100.5"))
    );
    assert_eq!(
        other_client.status,
        StatusCode::OK,
        "a different forwarded client has its own window"
    );
    let same_client = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-for", "198.51.100.4"))
    );
    assert_eq!(same_client.status, StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn an_ipv4_mapped_peer_matches_the_v4_list_entry() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let blocked = hit!(
        svc,
        TestRequest::get()
            .uri("/api")
            .peer_addr("[::ffff:203.0.113.9]:45000".parse().expect("addr"))
    );
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn a_forged_forwarded_proto_from_an_untrusted_peer_is_still_redirected() {
    let config = SecurityConfig {
        enforce_https: true,
        trust_x_forwarded_proto: true,
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let forged = hit!(
        svc,
        get("198.51.100.4", "/api").insert_header(("x-forwarded-proto", "https"))
    );
    assert_eq!(forged.status, StatusCode::MOVED_PERMANENTLY);
    let trusted = hit!(
        svc,
        get("10.0.0.1", "/api").insert_header(("x-forwarded-proto", "https"))
    );
    assert_eq!(trusted.status, StatusCode::OK);
}

#[actix_web::test]
async fn a_whitelisted_ip_is_exempt_from_the_user_agent_block() {
    let config = SecurityConfig {
        whitelist: Some(vec!["203.0.113.9".to_owned()]),
        blocked_user_agents: vec!["badbot".to_owned()],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let whitelisted = hit!(
        svc,
        get("203.0.113.9", "/api").insert_header(("user-agent", "badbot/1.0"))
    );
    assert_eq!(whitelisted.status, StatusCode::OK);
}

// --- from_security_config: every stage reachable ---

#[actix_web::test]
async fn the_country_rules_reach_the_geo_stage() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("US"))),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let blocked = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    let other = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("DE"))),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&other));
    let allowed = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(allowed.status, StatusCode::OK);
}

#[actix_web::test]
async fn the_endpoint_rate_limits_reach_the_limiter() {
    let mut endpoint_rate_limits = BTreeMap::new();
    endpoint_rate_limits.insert("/login".to_owned(), (1_u32, 60_u64));
    let config = SecurityConfig {
        endpoint_rate_limits,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let first = hit!(svc, get("203.0.113.9", "/login"));
    assert_eq!(first.status, StatusCode::OK);
    let second = hit!(svc, get("203.0.113.9", "/login"));
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
    let elsewhere = hit!(svc, get("203.0.113.9", "/other"));
    assert_eq!(elsewhere.status, StatusCode::OK);
}

#[actix_web::test]
async fn the_rate_limit_auto_ban_reaches_the_limiter() {
    let config = SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 1,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let first = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(first.status, StatusCode::OK);
    let crossing = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(crossing.status, StatusCode::TOO_MANY_REQUESTS);
    let banned = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
    assert_eq!(banned.body, actix_guard_rs::BANNED_MESSAGE);
}

#[actix_web::test]
async fn the_custom_request_check_reaches_the_pipeline() {
    let config = SecurityConfig {
        custom_request_check: Some(Arc::new(|ctx| {
            (ctx.path == "/teapot").then_some(guard_core_engine::custom_checks::CustomResponse {
                status: Some(418),
                body: None,
            })
        })),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let blocked = hit!(svc, get("203.0.113.9", "/teapot"));
    assert_eq!(blocked.status, StatusCode::IM_A_TEAPOT);
    let passed = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(passed.status, StatusCode::OK);
}

#[actix_web::test]
async fn the_global_auth_verifier_backs_the_route_authentication() {
    let config = SecurityConfig {
        auth_verifier: Some(Arc::new(|credential| credential == "good")),
        ..SecurityConfig::default()
    };
    let transform = from_config(&config).with_route_configs(Arc::new(|_method, _path| {
        Some(Arc::new(RouteConfig {
            auth_required: Some("bearer".to_owned()),
            ..RouteConfig::default()
        }))
    }));
    let svc = serve!(transform);
    let good = hit!(
        svc,
        get("203.0.113.9", "/api").insert_header(("authorization", "Bearer good"))
    );
    assert_eq!(good.status, StatusCode::OK);
    let bad = hit!(
        svc,
        get("203.0.113.9", "/api").insert_header(("authorization", "Bearer nope"))
    );
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn the_cors_expose_headers_reach_the_response() {
    let config = SecurityConfig {
        enable_cors: true,
        cors_allow_origins: vec!["https://app.example.com".to_owned()],
        cors_expose_headers: vec!["X-Trace".to_owned()],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let answered = hit!(
        svc,
        get("203.0.113.9", "/api").insert_header(("origin", "https://app.example.com"))
    );
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(
        header(&answered, "access-control-expose-headers").as_deref(),
        Some("X-Trace")
    );
    assert_eq!(header(&answered, "vary").as_deref(), Some("Origin"));
}

#[actix_web::test]
async fn the_config_modifier_runs_once_and_the_config_error_hook_reports() {
    let calls = Arc::new(Mutex::new(0_u32));
    let counter = Arc::clone(&calls);
    let config = SecurityConfig {
        custom_response_modifier: Some(Arc::new(move |bits| {
            *counter.lock().expect("counter") += 1;
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        })),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let answered = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(header(&answered, "x-modified").as_deref(), Some("yes"));
    assert_eq!(*calls.lock().expect("counter"), 1, "applied exactly once");

    let reported: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&reported);
    let panicking = SecurityConfig {
        custom_response_modifier: Some(Arc::new(|_bits| panic!("modifier exploded"))),
        on_error: Some(Arc::new(move |stage, _error, _context| {
            sink.lock().expect("sink").push(stage.to_owned());
        })),
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&panicking));
    let survived = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(survived.status, StatusCode::OK);
    assert_eq!(
        reported.lock().expect("sink").as_slice(),
        ["custom_response_modifier"]
    );
}

#[actix_web::test]
async fn a_return_rule_ban_is_enforced_by_the_ban_stage() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("status:200", 0)],
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    let first = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(first.status, StatusCode::OK);
    let banned = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
}

// --- the response pass ---

#[actix_web::test]
async fn the_modifier_runs_without_a_response_processor() {
    let transform =
        GuardTransform::new(default_config()).with_custom_response_modifier(Arc::new(|bits| {
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        }));
    let svc = serve!(transform);
    let answered = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(header(&answered, "x-modified").as_deref(), Some("yes"));
}

async fn secret_body_handler() -> HttpResponse {
    HttpResponse::Ok().body("the secret token is 42")
}

#[actix_web::test]
async fn a_return_rule_matches_the_response_body_and_the_body_is_re_emitted() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("secret", 0)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config), secret_body_handler);
    let first = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(
        first.body, "the secret token is 42",
        "the full body survives"
    );
    let banned = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(banned.status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn a_body_rule_does_not_match_a_clean_body() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("secret", 0)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config));
    for _ in 0..3 {
        let passed = hit!(svc, get("203.0.113.9", "/api"));
        assert_eq!(passed.status, StatusCode::OK);
        assert_eq!(passed.body, "ok");
    }
}

// --- all-checks-bypass routes ---

fn all_bypass_routes() -> actix_guard_rs::RouteConfigResolver {
    Arc::new(|_method, path| {
        (path == "/open").then(|| {
            Arc::new(RouteConfig {
                bypassed_checks: ["all".to_owned()].into_iter().collect(),
                ..RouteConfig::default()
            })
        })
    })
}

fn recording_bus() -> (
    Arc<guard_core_rs::events::SecurityEventBus>,
    Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>>,
) {
    let seen: Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let bus = guard_core_rs::events::SecurityEventBus::new(true).on_event(Arc::new(
        move |event: &guard_core_rs::events::SecurityEvent| {
            sink.lock().expect("sink").push(event.clone());
        },
    ));
    (Arc::new(bus), seen)
}

#[actix_web::test]
async fn an_all_bypass_route_skips_the_pipeline_emits_the_event_and_runs_only_the_modifier() {
    let (bus, seen) = recording_bus();
    let metrics_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let metrics_sink = Arc::clone(&metrics_seen);
    let collector = guard_core_rs::metrics::MetricsCollector::new(true).with_handler(Arc::new(
        move |metric: &guard_core_rs::metrics::SecurityMetric| {
            metrics_sink
                .lock()
                .expect("sink")
                .push(metric.metric_type.clone());
        },
    ));
    let config = SecurityConfig {
        custom_response_modifier: Some(Arc::new(|bits| {
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        })),
        ..SecurityConfig::default()
    };
    let transform = from_config(&config)
        .with_route_configs(all_bypass_routes())
        .with_event_bus(bus)
        .with_metrics(collector);
    let svc = serve!(transform);
    let bypassed = hit!(svc, get("203.0.113.9", &format!("/open?{ATTACK_QUERY}")));
    assert_eq!(bypassed.status, StatusCode::OK, "the attack is not scanned");
    assert_eq!(header(&bypassed, "x-modified").as_deref(), Some("yes"));
    assert_eq!(
        header(&bypassed, "x-content-type-options"),
        None,
        "no security headers on a fully bypassed route"
    );
    assert!(
        metrics_seen.lock().expect("sink").is_empty(),
        "no metrics on a fully bypassed route"
    );
    let events = seen.lock().expect("sink").clone();
    let bypass = events
        .iter()
        .find(|event| event.event_type == "security_bypass")
        .expect("the security_bypass event fired");
    assert_eq!(bypass.action_taken, "all_checks_bypassed");
    assert_eq!(
        bypass.reason,
        "Route configured to bypass all security checks"
    );
    let checked = hit!(svc, get("203.0.113.9", &format!("/guarded?{ATTACK_QUERY}")));
    assert_eq!(checked.status, StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn an_all_bypass_route_continues_through_the_pipeline_in_passive_mode() {
    let (bus, seen) = recording_bus();
    let config = SecurityConfig {
        passive_mode: true,
        ..SecurityConfig::default()
    };
    let transform = from_config(&config)
        .with_route_configs(all_bypass_routes())
        .with_event_bus(bus);
    let svc = serve!(transform);
    let passive = hit!(svc, get("203.0.113.9", "/open"));
    assert_eq!(passive.status, StatusCode::OK);
    assert_eq!(
        header(&passive, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "passive mode keeps the response pass"
    );
    assert!(
        seen.lock()
            .expect("sink")
            .iter()
            .any(|event| event.event_type == "security_bypass"),
        "the event still fires under passive mode"
    );
}

#[actix_web::test]
async fn a_streamed_response_with_a_status_only_rule_is_not_buffered() {
    // A status rule never reads the body, so the response streams through
    // untouched (a stream error would otherwise answer the fail-secure 500).
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("status:404", 5)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config), || async {
        HttpResponse::Ok().streaming(futures_stream())
    });
    let passed = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(passed.status, StatusCode::OK);
}

fn futures_stream() -> impl futures_core::Stream<Item = Result<bytes::Bytes, actix_web::Error>> {
    struct Chunks(u8);
    impl futures_core::Stream for Chunks {
        type Item = Result<bytes::Bytes, actix_web::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            if self.0 == 0 {
                return std::task::Poll::Ready(None);
            }
            self.0 -= 1;
            std::task::Poll::Ready(Some(Ok(bytes::Bytes::from_static(b"chunk"))))
        }
    }
    Chunks(2)
}

#[actix_web::test]
async fn a_response_body_read_error_fails_secure_when_a_body_rule_needs_it() {
    struct Failing;
    impl futures_core::Stream for Failing {
        type Item = Result<bytes::Bytes, actix_web::Error>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(Some(Err(actix_web::error::ErrorInternalServerError(
                "stream broke",
            ))))
        }
    }
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("secret", 1)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let svc = serve!(from_config(&config), || async {
        HttpResponse::Ok().streaming(Failing)
    });
    let failed = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.body, actix_guard_rs::FAILURE_MESSAGE);
}

#[actix_web::test]
async fn every_worker_clone_shares_one_set_of_stores() {
    // actix builds one service per worker from the same transform: the rate
    // limiter and the ban store built by `from_security_config` are shared.
    let config = SecurityConfig {
        rate_limit: 1,
        ..SecurityConfig::default()
    };
    let transform = from_config(&config);
    let worker_a = serve!(transform.clone());
    let worker_b = serve!(transform);
    let first = hit!(worker_a, get("203.0.113.9", "/api"));
    assert_eq!(first.status, StatusCode::OK);
    let second = hit!(worker_b, get("203.0.113.9", "/api"));
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn an_all_bypass_route_without_an_event_bus_still_forwards() {
    let transform = GuardTransform::with_defaults().with_route_configs(all_bypass_routes());
    let svc = serve!(transform);
    let bypassed = hit!(svc, get("203.0.113.9", &format!("/open?{ATTACK_QUERY}")));
    assert_eq!(bypassed.status, StatusCode::OK);
}

#[actix_web::test]
async fn a_bare_layer_without_a_read_timeout_buffers_the_body_for_the_rules() {
    let processor = guard_core_rs::process_response::ResponseProcessor::new(
        None,
        None,
        vec![return_rule("secret", 0)],
        Arc::new(Mutex::new(
            guard_core_engine::behavior::BehaviorTracker::new(),
        )),
        IpBanManager::new(),
        true,
        guard_core_engine::behavior::DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
        false,
    );
    let transform = GuardTransform::with_defaults().with_response_processor(processor);
    let svc = serve!(transform, secret_body_handler);
    let answered = hit!(svc, get("203.0.113.9", "/api"));
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(answered.body, "the secret token is 42");
}
