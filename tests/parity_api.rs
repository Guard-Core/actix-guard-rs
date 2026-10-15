//! The new public surface of the parity work: the client policy, the
//! exclusion marker, the wiring entry points (agent, dynamic rules, cloud
//! refresh, distributed stores) and the WebSocket client policy.

use actix_guard_rs::websocket::{WebSocketGuard, WebSocketGuardConfig};
use actix_guard_rs::{
    AgentStats, ClientPolicy, Distributed, GuardConfigError, GuardExclusionScoped, GuardTransform,
    IpBanManager, PathExclusions, Wiring, WiringOptions, default_config,
};
use actix_web::body::MessageBody;
use actix_web::dev::ServiceResponse;
use actix_web::http::StatusCode;
use actix_web::test::{TestRequest, call_service, init_service, read_body};
use actix_web::{App, HttpMessage, HttpRequest, HttpResponse, web};
use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::distributed::{BanStore, SlidingWindowStore, StoreError};
use guard_core_engine::security_config::SecurityConfig;
use guard_core_rs::composite::{TelemetryError, TelemetryHandler};
use guard_core_rs::events::SecurityEvent;
use guard_core_rs::metrics::SecurityMetric;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

async fn text<B: MessageBody>(response: ServiceResponse<B>) -> (StatusCode, String) {
    let status = response.status();
    (
        status,
        String::from_utf8_lossy(&read_body(response).await).into_owned(),
    )
}

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn marker_handler(request: HttpRequest) -> HttpResponse {
    let scoped = request.extensions().get::<GuardExclusionScoped>().is_some();
    HttpResponse::Ok().body(if scoped { "scoped" } else { "normal" })
}

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().expect("test ip"), 45_000)
}

fn get(ip: &str, uri: &str) -> TestRequest {
    TestRequest::get().uri(uri).peer_addr(peer(ip))
}

#[actix_web::test]
async fn an_excluded_request_carries_the_scoped_marker() {
    let transform =
        GuardTransform::from_security_config(&SecurityConfig::default()).expect("valid config");
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(marker_handler)),
    )
    .await;
    let (_, scoped) =
        text(call_service(&svc, get("203.0.113.9", "/docs").to_request()).await).await;
    assert_eq!(scoped, "scoped");
    let (_, normal) = text(call_service(&svc, get("203.0.113.9", "/api").to_request()).await).await;
    assert_eq!(normal, "normal");
}

#[test]
fn the_exclusions_accessor_reports_the_normalized_matcher() {
    let transform = GuardTransform::with_defaults()
        .with_exclude_paths(vec!["/docs/".to_owned(), "/a/../static".to_owned()]);
    assert_eq!(transform.exclude_paths(), ["/docs", "/static"]);
    let transform =
        GuardTransform::with_defaults().with_path_exclusions(PathExclusions::new(["/health"]));
    assert_eq!(transform.exclude_paths(), ["/health"]);
}

#[actix_web::test]
async fn a_bare_layer_adopts_the_client_policy_it_is_given() {
    let policy = ClientPolicy {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        trusted_proxy_depth: 1,
        fail_secure: true,
    };
    let transform = GuardTransform::new(default_config())
        .with_ip_gate(
            actix_guard_rs::IpGateConfig::new([] as [&str; 0], ["203.0.113.7"], [] as [&str; 0])
                .expect("valid lists"),
        )
        .with_client_policy(policy.clone());
    assert_eq!(transform.client_policy(), &policy);
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (blocked, _) = text(
        call_service(
            &svc,
            get("10.0.0.1", "/api")
                .insert_header(("x-forwarded-for", "203.0.113.7"))
                .to_request(),
        )
        .await,
    )
    .await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);
    let (rejected, body) =
        text(call_service(&svc, TestRequest::get().uri("/api").to_request()).await).await;
    assert_eq!(rejected, StatusCode::FORBIDDEN);
    assert_eq!(body, "Client address could not be determined");
}

#[test]
fn an_unknown_cloud_provider_selector_fails_closed() {
    let config = SecurityConfig {
        block_cloud_providers: Some(["NotACloud".to_owned()].into_iter().collect()),
        ..SecurityConfig::default()
    };
    let error = GuardTransform::from_security_config(&config).expect_err("rejected");
    assert!(matches!(error, GuardConfigError::Cloud(_)), "{error}");
    assert!(error.to_string().contains("block_cloud_providers"));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn country_rules_without_a_resolver_fail_closed() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        ..SecurityConfig::default()
    };
    let error = GuardTransform::from_security_config(&config).expect_err("rejected");
    assert!(matches!(error, GuardConfigError::Geo(_)), "{error}");
    assert!(error.to_string().starts_with("geo:"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn a_redis_error_renders_its_message() {
    let error = GuardConfigError::Redis("boom".to_owned());
    assert_eq!(error.to_string(), "redis: boom");
    assert!(std::error::Error::source(&error).is_none());
}

// --- the agent seam ---

#[derive(Default)]
struct Sink {
    events: AtomicUsize,
    metrics: AtomicUsize,
    polls: AtomicUsize,
    fail_start: bool,
}

impl TelemetryHandler for Sink {
    fn handler_name(&self) -> &'static str {
        "Sink"
    }
    fn start(&self) -> Result<(), TelemetryError> {
        if self.fail_start {
            Err(TelemetryError("start failed".to_owned()))
        } else {
            Ok(())
        }
    }
    fn stop(&self) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
        self.events.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
        self.metrics.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    fn health_check(&self) -> bool {
        true
    }
}

fn agent_config() -> SecurityConfig {
    SecurityConfig {
        enable_agent: true,
        agent_api_key: Some("a-key-of-at-least-ten".to_owned()),
        agent_enable_events: true,
        agent_enable_metrics: true,
        rate_limit: 1,
        ..SecurityConfig::default()
    }
}

#[test]
fn agent_stats_is_disabled_without_an_agent() {
    let transform =
        GuardTransform::from_security_config(&SecurityConfig::default()).expect("valid config");
    assert_eq!(
        transform.agent_stats(),
        AgentStats {
            enabled: false,
            degraded: false
        }
    );
    assert!(transform.telemetry().is_none());
    assert!(transform.spawn_dynamic_rules().is_none());
}

#[actix_web::test]
async fn the_injected_agent_receives_the_events_and_metrics() {
    let sink = Arc::new(Sink::default());
    let transform = GuardTransform::from_security_config_with(
        &agent_config(),
        &WiringOptions {
            agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    assert_eq!(
        transform.agent_stats(),
        AgentStats {
            enabled: true,
            degraded: false
        }
    );
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (first, _) = text(call_service(&svc, get("203.0.113.9", "/api").to_request()).await).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _) = text(call_service(&svc, get("203.0.113.9", "/api").to_request()).await).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        sink.metrics.load(Ordering::SeqCst) > 0,
        "the forwarded request reached the agent as a metric"
    );
    assert!(
        sink.events.load(Ordering::SeqCst) > 0,
        "the rate-limit crossing reached the agent as an event"
    );
}

#[test]
fn a_degraded_agent_start_shows_in_the_stats() {
    let sink = Arc::new(Sink {
        fail_start: true,
        ..Sink::default()
    });
    let transform = GuardTransform::from_security_config_with(
        &agent_config(),
        &WiringOptions {
            agent: Some(sink as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    transform.telemetry().expect("telemetry").start();
    assert_eq!(
        transform.agent_stats(),
        AgentStats {
            enabled: true,
            degraded: true
        }
    );
}

#[test]
fn the_dynamic_rule_poll_loop_is_host_started() {
    let sink = Arc::new(Sink::default());
    let config = SecurityConfig {
        enable_dynamic_rules: true,
        dynamic_rule_interval: 1,
        ..agent_config()
    };
    // The unvalidated seam: the poll loop test runs on a one second interval,
    // below the validated range.
    let wiring = Wiring::build_unvalidated(
        &config,
        &WiringOptions {
            agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    let transform = GuardTransform::from_wiring(wiring);
    assert_eq!(
        sink.polls.load(Ordering::SeqCst),
        0,
        "wiring never spawns the loop"
    );
    let handle = transform.spawn_dynamic_rules().expect("a poll loop");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sink.polls.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        sink.polls.load(Ordering::SeqCst) > 0,
        "the loop polled the agent"
    );
    drop(handle);
}

// --- wiring parts: cloud, distributed ---

#[actix_web::test]
async fn the_cloud_stage_and_its_refresh_are_wired_from_the_config() {
    let config = SecurityConfig {
        block_cloud_providers: Some(["AWS".to_owned()].into_iter().collect()),
        ..SecurityConfig::default()
    };
    let mut wiring = Wiring::from_security_config(&config).expect("wired");
    let refresh = wiring.cloud_refresh.as_mut().expect("a refresh seam");
    refresh
        .table
        .set_provider_ranges("AWS", vec![("198.51.100.0/24".to_owned(), None)])
        .expect("ranges");
    // Keep the background refresh off the network (and from clearing the
    // ranges a failed fetch would): the scheduler has no providers.
    let scheduler =
        guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new().with_providers(Vec::new());
    refresh.scheduler = Arc::new(scheduler);
    let transform = GuardTransform::from_wiring(wiring);
    let svc = init_service(
        App::new()
            .wrap(transform.clone())
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (blocked, body) =
        text(call_service(&svc, get("198.51.100.5", "/api").to_request()).await).await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);
    assert_eq!(body, "Cloud provider IP not allowed");
    let (allowed, _) =
        text(call_service(&svc, get("203.0.113.9", "/api").to_request()).await).await;
    assert_eq!(allowed, StatusCode::OK);
    // The global cloud rules also apply on an excluded path.
    let (scoped, scoped_body) =
        text(call_service(&svc, get("198.51.100.77", "/docs").to_request()).await).await;
    assert_eq!(scoped, StatusCode::FORBIDDEN);
    assert_eq!(scoped_body, "Cloud provider IP not allowed");
    // The maintenance call drives the same wired scheduler.
    let _scheduled = transform.refresh_cloud_ip_ranges();
}

struct MemoryWindowStore(Mutex<HashMap<String, Vec<f64>>>);

impl SlidingWindowStore for MemoryWindowStore {
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError> {
        let mut windows = self.0.lock().expect("windows");
        let hits = windows.entry(key.to_owned()).or_default();
        hits.retain(|hit| now - hit < f64::from(u32::try_from(window).unwrap_or(u32::MAX)));
        hits.push(now);
        Ok(hits.len() as u64)
    }
}

struct MemoryBanStore(Mutex<HashMap<String, f64>>);

impl BanStore for MemoryBanStore {
    fn set_ban(&self, key: &str, expiry: f64, _ttl_seconds: u64) -> Result<(), StoreError> {
        self.0.lock().expect("bans").insert(key.to_owned(), expiry);
        Ok(())
    }
    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError> {
        Ok(self.0.lock().expect("bans").get(key).copied())
    }
    fn delete_ban(&self, key: &str) -> Result<(), StoreError> {
        self.0.lock().expect("bans").remove(key);
        Ok(())
    }
}

#[actix_web::test]
async fn the_wired_distributed_stores_carry_the_rate_limit_and_the_ban() {
    let config = SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 1,
        ..SecurityConfig::default()
    };
    let ban_store = Arc::new(MemoryBanStore(Mutex::new(HashMap::new())));
    let mut wiring = Wiring::from_security_config(&config).expect("wired");
    wiring.distributed = Some(Distributed {
        window_store: Arc::new(MemoryWindowStore(Mutex::new(HashMap::new()))),
        ban_store: Arc::clone(&ban_store) as Arc<dyn BanStore>,
        prefix: "guard_core:".to_owned(),
        fail_open: false,
    });
    let svc = init_service(
        App::new()
            .wrap(GuardTransform::from_wiring(wiring))
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (first, _) = text(call_service(&svc, get("192.0.2.77", "/api").to_request()).await).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _) = text(call_service(&svc, get("192.0.2.77", "/api").to_request()).await).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        ban_store
            .0
            .lock()
            .expect("bans")
            .contains_key("guard_core:banned_ips:192.0.2.77"),
        "the auto-ban wrote through the wired ban store"
    );
}

// --- the response body timeout ---

struct Hang;

impl futures_core::Stream for Hang {
    type Item = Result<bytes::Bytes, actix_web::Error>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}

#[actix_web::test]
async fn a_stalled_response_body_times_out_fail_secure() {
    let config = SecurityConfig {
        global_behavior_rules: vec![BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold: 1,
            window: 60,
            pattern: "secret".to_owned(),
            action: "ban".to_owned(),
            ban_duration: Some(60),
            correlate_with_detection: false,
        }],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let transform = GuardTransform::from_security_config(&config)
        .expect("valid config")
        .with_body_read_timeout(Duration::from_millis(100));
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(|| async { HttpResponse::Ok().streaming(Hang) })),
    )
    .await;
    let (status, body) =
        text(call_service(&svc, get("203.0.113.9", "/api").to_request()).await).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, actix_guard_rs::FAILURE_MESSAGE);
}

// --- the WebSocket guard resolves the client like the HTTP guard ---

#[actix_web::test]
async fn the_websocket_guard_resolves_the_forwarded_client() {
    let manager = IpBanManager::new();
    manager
        .ban_ip("203.0.113.7".parse().expect("ip"), 600, "test ban")
        .expect("ban");
    let config = WebSocketGuardConfig::new(default_config())
        .with_ip_banning(manager)
        .with_client_policy(ClientPolicy {
            trusted_proxies: vec!["10.0.0.0/8".to_owned()],
            trusted_proxy_depth: 1,
            fail_secure: true,
        });
    let svc = init_service(
        App::new()
            .wrap(WebSocketGuard::new(config))
            .route("/ws", web::get().to(ok_handler)),
    )
    .await;
    let upgrade = |ip: &str, forwarded: &str| {
        get(ip, "/ws")
            .insert_header(("upgrade", "websocket"))
            .insert_header(("connection", "Upgrade"))
            .insert_header(("x-forwarded-for", forwarded.to_owned()))
            .to_request()
    };
    let banned = call_service(&svc, upgrade("10.0.0.1", "203.0.113.7")).await;
    assert_eq!(banned.status(), StatusCode::FORBIDDEN);
    let allowed = call_service(&svc, upgrade("10.0.0.1", "198.51.100.4")).await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let unresolved = call_service(
        &svc,
        TestRequest::get()
            .uri("/ws")
            .insert_header(("upgrade", "websocket"))
            .insert_header(("connection", "Upgrade"))
            .to_request(),
    )
    .await;
    assert_eq!(unresolved.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn the_wiring_parts_install_one_by_one_on_a_bare_layer() {
    let config = SecurityConfig {
        enable_dynamic_rules: true,
        block_cloud_providers: Some(["AWS".to_owned()].into_iter().collect()),
        ..agent_config()
    };
    let wiring = Wiring::from_security_config_with(
        &config,
        &WiringOptions {
            agent: Some(Arc::new(Sink::default()) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("wired");
    let mut refresh = wiring.cloud_refresh.clone().expect("refresh");
    refresh.scheduler = Arc::new(
        guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new().with_providers(Vec::new()),
    );
    let transform = GuardTransform::new(default_config())
        .with_telemetry(Arc::clone(wiring.telemetry.as_ref().expect("telemetry")))
        .with_dynamic_rules(wiring.dynamic_rules.clone().expect("rules"))
        .with_cloud_refresh(refresh)
        .with_auth_verifier(Arc::new(|credential| credential == "good"))
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(guard_core_engine::route_config::RouteConfig {
                auth_required: Some("bearer".to_owned()),
                // A zero rate limit is an invalid tier: the route fails secure.
                ..guard_core_engine::route_config::RouteConfig::default()
            }))
        }));
    assert!(transform.agent_stats().enabled);
    drop(transform.spawn_dynamic_rules().expect("a loop"));
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (good, _) = text(
        call_service(
            &svc,
            get("203.0.113.9", "/api")
                .insert_header(("authorization", "Bearer good"))
                .to_request(),
        )
        .await,
    )
    .await;
    assert_eq!(good, StatusCode::OK);
}

#[actix_web::test]
async fn an_invalid_route_tier_on_an_excluded_path_fails_secure() {
    let transform = GuardTransform::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(guard_core_engine::route_config::RouteConfig {
                rate_limit: Some(0),
                ..guard_core_engine::route_config::RouteConfig::default()
            }))
        }));
    let svc = init_service(
        App::new()
            .wrap(transform)
            .default_service(web::to(ok_handler)),
    )
    .await;
    let (status, body) =
        text(call_service(&svc, get("203.0.113.9", "/docs").to_request()).await).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, actix_guard_rs::FAILURE_MESSAGE);
}
