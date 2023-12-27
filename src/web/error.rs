use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(Debug, Clone, serde::Serialize)]
struct ErrorResponseBody {
    error: String,
}

// NOTE: The error description must not contain any sensitive information!
#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum AppError {
    #[error("Internal server error")]
    InternalServerError,
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("Invalid Authorization header")]
    InvalidAuthorizationHeader,
    #[error("Session expired")]
    SessionExpired,
    #[error("Not authorized")]
    Unauthorized,
    #[error("URL not found")]
    UrlNotFound,
    #[error("{0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let api_error = ErrorResponseBody {
            error: self.to_string(),
        };

        let response_code = match self {
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotLoggedIn
            | AppError::InvalidAuthorizationHeader
            | AppError::SessionExpired => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized => StatusCode::FORBIDDEN,
            AppError::UrlNotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
        };

        (response_code, Json(api_error)).into_response()
    }
}

pub(super) type AppResult<T> = Result<T, AppError>;
