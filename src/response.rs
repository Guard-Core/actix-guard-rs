//! Short-circuit responses emitted by the guard.

use actix_web::dev::ServiceResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_TYPE, RETRY_AFTER};
use actix_web::{HttpRequest, HttpResponse};

/// Detail message carried by the `400 Bad Request` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the IP gate's `403 Forbidden` response.
pub const FORBIDDEN_MESSAGE: &str = "Forbidden";

/// Detail message carried by the ban stage's `403 Forbidden` response.
pub const BANNED_MESSAGE: &str = "IP address banned";

/// Detail message carried by the `403 Forbidden` response when a detected
/// threat crossed an auto-ban threshold and the ban fired on this request.
pub const ACTIVITY_BANNED_MESSAGE: &str = "IP has been banned";

/// Detail message carried by the `429 Too Many Requests` response.
pub const RATE_LIMITED_MESSAGE: &str = "Too many requests";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn oversize(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure(request: HttpRequest) -> ServiceResponse {
    plain_text(request, StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The HTTPS-enforcement redirect: the reference status with the
/// scheme-upgraded `Location` target and an empty body.
pub(crate) fn redirect(
    request: HttpRequest,
    redirect: &guard_core_rs::https_enforcement::HttpsRedirectAnswer,
) -> ServiceResponse {
    let status = StatusCode::from_u16(redirect.status).expect("reference status");
    let mut response = HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body("");
    response.headers_mut().insert(
        actix_web::http::header::LOCATION,
        redirect
            .location
            .parse()
            .expect("the composed location is a valid header value"),
    );
    ServiceResponse::new(request, response)
}

/// Land the response-side pass's headers (security headers + CORS verdict)
/// on a response.
pub(crate) fn apply_headers(
    response: &mut HttpResponse,
    headers: Option<actix_web::http::header::HeaderMap>,
) {
    let Some(headers) = headers else {
        return;
    };
    for (name, value) in headers {
        #[cfg(not(coverage))] // unreachable: the entries arrive in
        // already-validated header types, so neither re-parse can fail
        let Ok(name) = actix_web::http::header::HeaderName::try_from(name.as_str()) else {
            continue;
        };
        #[cfg(not(coverage))]
        let Ok(value) = actix_web::http::header::HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        #[cfg(coverage)]
        let name = actix_web::http::header::HeaderName::try_from(name.as_str())
            .expect("already-validated header names re-parse");
        #[cfg(coverage)]
        let value = actix_web::http::header::HeaderValue::from_bytes(value.as_bytes())
            .expect("already-validated header values re-parse");
        response.headers_mut().insert(name, value);
    }
}

/// The engine stage's block answer rendered in the family shape: the
/// custom-error body override wins over the reference default message, and
/// the throttled shape carries `Retry-After: <window seconds>`.
pub(crate) fn stage(
    request: HttpRequest,
    stage: &guard_core_rs::tower::StageResponse,
) -> ServiceResponse {
    let status = StatusCode::from_u16(stage.status.as_u16()).expect("a valid stage status");
    let mut response = match &stage.custom_body {
        Some(body) => HttpResponse::build(status)
            .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
            .body(body.clone()),
        None => HttpResponse::build(status)
            .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
            .body(stage.body),
    };
    if let Some(retry_after) = stage.retry_after {
        response
            .headers_mut()
            .insert(RETRY_AFTER, retry_after.to_string().parse().expect("ascii"));
    }
    ServiceResponse::new(request, response)
}

/// The family block shape with a composed body override.
pub(crate) fn blocked_with_body(
    request: HttpRequest,
    status: u16,
    message: &str,
) -> ServiceResponse {
    let status = StatusCode::from_u16(status).expect("a valid block status");
    let response = HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(message.to_owned());
    ServiceResponse::new(request, response)
}

/// The ecosystem's error shape: the bare message as the body,
/// `text/plain; charset=utf-8` (same as the Python family).
fn plain_text(request: HttpRequest, status: StatusCode, message: &'static str) -> ServiceResponse {
    let response = HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(message);
    ServiceResponse::new(request, response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use bytes::Bytes;

    fn test_request() -> HttpRequest {
        actix_web::test::TestRequest::default().to_http_request()
    }

    #[test]
    fn forbidden_response_shape() {
        let response = blocked_with_body(test_request(), 403, FORBIDDEN_MESSAGE);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Forbidden")
        );
    }

    #[test]
    fn oversize_response_shape() {
        let response = oversize(test_request());
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Payload too large")
        );
    }

    #[test]
    fn failure_response_shape() {
        let response = failure(test_request());
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.into_body().try_into_bytes().expect("bytes"),
            Bytes::from_static(b"Security check failed")
        );
    }

    #[test]
    fn apply_headers_skips_a_missing_header_set() {
        let mut response = HttpResponse::Ok().finish();
        apply_headers(&mut response, None);
        assert!(
            response.headers().get("x-content-type-options").is_none(),
            "no header set: nothing applied"
        );
    }
}
