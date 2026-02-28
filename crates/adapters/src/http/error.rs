use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use domain::auth::error::AuthError;
use domain::common::error::DomainError;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorDetail {
    /// Machine-readable error code (e.g. `RULE_NOT_FOUND`).
    #[schema(value_type = String)]
    code: &'static str,
    /// Human-readable description of the error.
    message: String,
}

/// Standard API error type.
///
/// All variants produce a JSON response matching:
/// `{"error":{"code":"SCREAMING_SNAKE","message":"human-readable"}}`.
#[derive(Debug)]
pub enum ApiError {
    NotFound { code: &'static str, message: String },
    BadRequest { code: &'static str, message: String },
    Unauthorized { message: String },
    Forbidden { code: &'static str, message: String },
    Conflict { code: &'static str, message: String },
    Internal { message: String },
    ServiceUnavailable { message: String },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::NotFound { code, message } => (StatusCode::NOT_FOUND, code, message),
            Self::BadRequest { code, message } => (StatusCode::BAD_REQUEST, code, message),
            Self::Unauthorized { message } => {
                (StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED", message)
            }
            Self::Forbidden { code, message } => (StatusCode::FORBIDDEN, code, message),
            Self::Conflict { code, message } => (StatusCode::CONFLICT, code, message),
            Self::Internal { message } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
            }
            Self::ServiceUnavailable { message } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                message,
            ),
        };

        (
            status,
            Json(ErrorBody {
                error: ErrorDetail { code, message },
            }),
        )
            .into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Forbidden(ref msg) => Self::Forbidden {
                code: "NAMESPACE_FORBIDDEN",
                message: msg.clone(),
            },
            _ => Self::Unauthorized {
                message: err.to_string(),
            },
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        match &err {
            DomainError::RuleNotFound(_) => Self::NotFound {
                code: "RULE_NOT_FOUND",
                message: err.to_string(),
            },
            DomainError::DuplicateRule(_) => Self::Conflict {
                code: "DUPLICATE_RULE",
                message: err.to_string(),
            },
            DomainError::InvalidRule(_) | DomainError::InvalidConfig(_) => Self::BadRequest {
                code: "VALIDATION_ERROR",
                message: err.to_string(),
            },
            DomainError::EngineError(_) => Self::Internal {
                message: err.to_string(),
            },
            DomainError::PermissionDenied(_) => Self::Forbidden {
                code: "PERMISSION_DENIED",
                message: err.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn response_body(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn not_found_produces_correct_json() {
        let err = ApiError::NotFound {
            code: "RULE_NOT_FOUND",
            message: "Rule fw-999 not found".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "RULE_NOT_FOUND");
        assert_eq!(body["error"]["message"], "Rule fw-999 not found");
    }

    #[tokio::test]
    async fn bad_request_produces_correct_json() {
        let err = ApiError::BadRequest {
            code: "INVALID_RULE",
            message: "priority must be > 0".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_RULE");
    }

    #[tokio::test]
    async fn internal_error_produces_correct_json() {
        let err = ApiError::Internal {
            message: "unexpected failure".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    }

    #[tokio::test]
    async fn conflict_produces_correct_json() {
        let err = ApiError::Conflict {
            code: "DUPLICATE_RULE",
            message: "rule fw-001 already exists".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "DUPLICATE_RULE");
    }

    #[tokio::test]
    async fn domain_rule_not_found_maps_to_404() {
        let err = ApiError::from(DomainError::RuleNotFound("fw-999".to_string()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "RULE_NOT_FOUND");
    }

    #[tokio::test]
    async fn domain_duplicate_maps_to_409() {
        let err = ApiError::from(DomainError::DuplicateRule("fw-001".to_string()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "DUPLICATE_RULE");
    }

    #[tokio::test]
    async fn domain_invalid_rule_maps_to_400() {
        let err = ApiError::from(DomainError::InvalidRule("bad priority".to_string()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
    }

    #[tokio::test]
    async fn unauthorized_produces_correct_json() {
        let err = ApiError::Unauthorized {
            message: "token expired".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "AUTHENTICATION_REQUIRED");
        assert_eq!(body["error"]["message"], "token expired");
    }

    #[tokio::test]
    async fn auth_error_maps_to_401() {
        let err = ApiError::from(AuthError::TokenExpired);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn forbidden_produces_correct_json() {
        let err = ApiError::Forbidden {
            code: "NAMESPACE_FORBIDDEN",
            message: "access denied: namespace 'prod'".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "NAMESPACE_FORBIDDEN");
        assert_eq!(body["error"]["message"], "access denied: namespace 'prod'");
    }

    #[tokio::test]
    async fn auth_forbidden_maps_to_403() {
        let err = ApiError::from(AuthError::Forbidden("namespace denied".to_string()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "NAMESPACE_FORBIDDEN");
    }

    #[tokio::test]
    async fn service_unavailable_produces_correct_json() {
        let err = ApiError::ServiceUnavailable {
            message: "eBPF not loaded".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = response_body(resp).await;
        assert_eq!(body["error"]["code"], "SERVICE_UNAVAILABLE");
    }
}
