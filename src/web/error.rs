use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Template)]
#[template(path = "unprotected/error.html")]
struct ErrorTemplate<'a> {
    error: &'a str,
}

// NOTE: The error description must not contain any sensitive information!
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum AppError {
    #[error("Internal server error")]
    InternalServerError,
    #[error("Not authorized")]
    Unauthorized,
    #[error("URL not found")]
    UrlNotFound,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error = self.to_string();
        let error_template = ErrorTemplate { error: &error };

        let response_code = match self {
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unauthorized => StatusCode::FORBIDDEN,
            AppError::UrlNotFound => StatusCode::NOT_FOUND,
        };

        (response_code, error_template).into_response()
    }
}

pub(crate) type AppResult<T> = Result<T, AppError>;
