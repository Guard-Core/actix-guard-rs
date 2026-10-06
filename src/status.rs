//! The status route, ported from fastapi-guard `guard/status.py`
//! (`add_status_route`) serving the payload of
//! `HandlerInitializer.get_initialization_status`
//! (`guard_core/core/initialization/handler_initializer.py`): the
//! cloud-provider readiness table and the geo-ip component.
//!
//! The Rust engine tracks the cloud table's readiness only
//! ([`CloudIpTable::provider_is_ready`] is "the reference `get_status`'s
//! `ready` flag"), so each provider row carries `ready` alone - the
//! `entries`/`last_refreshed` keys the Python family serves have no engine
//! surface here and are not invented. The geo-ip component is `null` when no
//! handler is configured and `{"configured":true}` when one is: the engine
//! exposes no geo health readout ([`guard_core_engine::geo::GeoIpHandler`] is the lookup trait).
//!
//! # Example
//!
//! ```
//! use actix_guard_rs::status::GuardStatus;
//! use actix_web::{App, http::StatusCode, test};
//!
//! # let runtime = actix_web::rt::System::new();
//! # runtime.block_on(async {
//! let service = test::init_service(App::new().service(GuardStatus::new())).await;
//! let request = test::TestRequest::get().uri("/_guard/status").to_request();
//! let response = test::call_service(&service, request).await;
//! assert_eq!(response.status(), StatusCode::OK);
//! # });
//! ```

use actix_web::HttpResponse;
use actix_web::Resource;
use actix_web::dev::{AppService, HttpServiceFactory};
use actix_web::http::StatusCode;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::web::get;
use guard_core_engine::cloud_provider::{CloudIpTable, VALID_CLOUD_PROVIDERS};
use std::fmt::Write;

/// The path `add_status_route` registers by default (the reference's
/// `/_guard/status`).
pub const DEFAULT_STATUS_PATH: &str = "/_guard/status";

/// The initialization-status snapshot the status route serves.
///
/// Build it with the handles the application already owns: the
/// [`CloudIpTable`] the cloud-provider stage was built from (clones share
/// the store, so the snapshot always answers from the live table), and
/// whether a [`guard_core_engine::geo::GeoIpHandler`] is configured.
///
/// The payload is serialized by hand (the crate carries no JSON
/// dependency); the shape is the reference's `get_initialization_status`
/// mapping with the caveats documented at the module level.
#[derive(Debug, Clone, Default)]
pub struct GuardStatus {
    cloud: Option<CloudIpTable>,
    geo_configured: bool,
}

impl GuardStatus {
    /// A snapshot with no cloud table and no geo handler: every provider
    /// reports `ready:false` and `geo_ip` is `null`, the reference's
    /// never-initialized shape.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve the readiness flags from this cloud table (the one the
    /// cloud-provider stage consults; clones share the store, so a
    /// background refresher's swaps are visible).
    #[must_use]
    pub fn with_cloud_table(mut self, cloud: CloudIpTable) -> Self {
        self.cloud = Some(cloud);
        self
    }

    /// Mark the geo-ip component configured (`{"configured":true}` instead
    /// of `null`).
    #[must_use]
    pub const fn with_geo_configured(mut self, geo_configured: bool) -> Self {
        self.geo_configured = geo_configured;
        self
    }

    /// The cloud providers with their readiness flags, in the engine's
    /// reference order.
    #[must_use]
    pub fn cloud_provider_status(&self) -> Vec<(&'static str, bool)> {
        VALID_CLOUD_PROVIDERS
            .iter()
            .map(|provider| {
                let ready = self
                    .cloud
                    .as_ref()
                    .is_some_and(|table| table.provider_is_ready(provider));
                (*provider, ready)
            })
            .collect()
    }

    /// The JSON document the status route serves.
    #[must_use]
    pub fn payload(&self) -> String {
        let mut payload = String::from(r#"{"cloud_providers":{"#);
        let mut first = true;
        for (provider, ready) in self.cloud_provider_status() {
            if first {
                first = false;
            } else {
                payload.push(',');
            }
            payload.push_str(&json_string(provider));
            payload.push_str(r#":{"ready":"#);
            payload.push_str(if ready { "true" } else { "false" });
            payload.push('}');
        }
        payload.push_str("},");
        if self.geo_configured {
            payload.push_str(r#""geo_ip":{"configured":true}"#);
        } else {
            payload.push_str(r#""geo_ip":null"#);
        }
        payload.push('}');
        payload
    }

    /// The status answer: `200 OK`, `application/json`, the snapshot
    /// document.
    #[must_use]
    pub fn response(&self) -> HttpResponse {
        HttpResponse::build(StatusCode::OK)
            .insert_header((CONTENT_TYPE, "application/json"))
            .body(self.payload())
    }
}

/// The `add_status_route` mirror: mount the snapshot as a resource with
/// `App::service(GuardStatus::new().with_cloud_table(table))`. The resource
/// answers `GET` [`DEFAULT_STATUS_PATH`] only.
impl HttpServiceFactory for GuardStatus {
    fn register(self, config: &mut AppService) {
        Resource::new(DEFAULT_STATUS_PATH)
            .route(get().to(move || {
                let status = self.clone();
                async move { status.response() }
            }))
            .register(config);
    }
}

/// The `HttpRequest`-taking form of the status answer, for applications that
/// mount the handler by hand (`web::get().to(status::handler)` with the
/// snapshot in `app_data`).
#[must_use]
pub fn handler(status: &GuardStatus) -> HttpResponse {
    status.response()
}

/// Escape one JSON string body: the two mandatory controls plus the
/// characters every consumer chokes on. The provider names this module
/// serializes are static ASCII, so the escape exists for completeness and
/// for any future dynamic key.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{TestRequest, call_service, init_service, read_body};
    use actix_web::web;

    #[test]
    fn empty_snapshot_reports_every_provider_unready_and_null_geo() {
        let payload = GuardStatus::new().payload();
        assert_eq!(
            payload,
            "{\"cloud_providers\":{\
             \"AWS\":{\"ready\":false},\
             \"GCP\":{\"ready\":false},\
             \"Azure\":{\"ready\":false},\
             \"DigitalOcean\":{\"ready\":false},\
             \"Linode\":{\"ready\":false},\
             \"Vultr\":{\"ready\":false}},\
             \"geo_ip\":null}"
        );
    }

    #[test]
    fn cloud_table_readiness_passes_through() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        let status = GuardStatus::new().with_cloud_table(table);
        let providers = status.cloud_provider_status();
        assert_eq!(providers.len(), 6);
        let aws = providers.iter().find(|(name, _)| *name == "AWS");
        assert_eq!(aws.copied(), Some(("AWS", true)));
        assert!(
            providers
                .iter()
                .all(|(name, ready)| *name == "AWS" || !ready)
        );
        let payload = status.payload();
        assert!(payload.contains(r#""AWS":{"ready":true}"#));
        assert!(payload.contains(r#""GCP":{"ready":false}"#));
    }

    #[test]
    fn geo_configured_flips_the_component_object() {
        let configured = GuardStatus::new().with_geo_configured(true).payload();
        assert!(configured.contains(r#""geo_ip":{"configured":true}"#));
        let plain = GuardStatus::new().payload();
        assert!(plain.contains(r#""geo_ip":null"#));
    }

    #[test]
    fn clearing_a_provider_reports_it_unready_again() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("Vultr", vec![("192.0.2.1/32".to_owned(), None)])
            .expect("valid ranges");
        let snapshot = GuardStatus::new().with_cloud_table(table.clone());
        assert!(
            snapshot
                .cloud_provider_status()
                .iter()
                .any(|(name, ready)| *name == "Vultr" && *ready)
        );
        // The failed-refresh shape: the refresher drops the provider and the
        // snapshot follows (clones share the store).
        table.clear_provider("Vultr");
        assert!(
            !snapshot
                .cloud_provider_status()
                .iter()
                .any(|(_, ready)| *ready)
        );
    }

    #[test]
    fn json_string_escapes_the_control_family() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b\\c\nd\r\te"), "\"a\\\"b\\\\c\\nd\\r\\te\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }

    #[actix_web::test]
    async fn service_factory_mounts_the_default_path() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("GCP", vec![("198.51.100.0/24".to_owned(), None)])
            .expect("valid ranges");
        let service =
            init_service(actix_web::App::new().service(GuardStatus::new().with_cloud_table(table)))
                .await;
        let request = TestRequest::get().uri(DEFAULT_STATUS_PATH).to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/json"
        );
        let body = read_body(response).await;
        assert!(String::from_utf8_lossy(&body).contains(r#""GCP":{"ready":true}"#));
    }

    #[actix_web::test]
    async fn status_resource_answers_get_only() {
        let service = init_service(actix_web::App::new().service(GuardStatus::new())).await;
        let request = TestRequest::post().uri(DEFAULT_STATUS_PATH).to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// The `HttpRequest`-taking handler form stays available for hand
    /// mounting through `app_data`.
    #[actix_web::test]
    async fn handler_form_renders_from_app_data() {
        let service = init_service(
            actix_web::App::new()
                .app_data(web::Data::new(GuardStatus::new().with_geo_configured(true)))
                .route(
                    DEFAULT_STATUS_PATH,
                    actix_web::web::get().to(
                        |status: actix_web::web::Data<GuardStatus>| async move { handler(&status) },
                    ),
                ),
        )
        .await;
        let request = TestRequest::get().uri(DEFAULT_STATUS_PATH).to_request();
        let response = call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(String::from_utf8_lossy(&body).contains(r#""geo_ip":{"configured":true}"#));
    }
}
