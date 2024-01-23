use askama::Template;
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use axum_login::AuthUser;
use tokio::try_join;
use tracing::error;

use crate::{
    repository::{RedirectStatistic, ShortenedUrl},
    users::AuthSession,
    web::app::AppState,
    web::error::{AppError, AppResult},
};

#[derive(Template)]
#[template(path = "protected/home.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
}

#[derive(Template)]
#[template(path = "protected/shorten.html")]
struct ShortenUrlTemplate<'a> {
    initial_url: &'a str,
    shortened_url: Option<&'a str>,
    error_message: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "protected/url_list.html")]
struct UrlListTemplate<'a> {
    shortened_url_base: &'a str,
    active_urls: &'a [ShortenedUrl],
    error_message: Option<&'a str>,
    success_message: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "protected/url_details.html")]
struct UrlDetailsTemplate<'a> {
    shortened_url_base: &'a str,
    url: &'a ShortenedUrl,
    statistic: &'a RedirectStatistic,
}

#[derive(Debug, serde::Deserialize)]
pub struct ShortenUrl {
    url: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteResult {
    delete_success: Option<bool>,
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::protected))
        .route(
            "/shorten",
            get(self::get::shorten).post(self::post::shorten),
        )
        .route("/urls", get(self::get::list_urls))
        .nest(
            "/urls/:id",
            Router::new()
                .route("/", get(self::get::url_details))
                .route("/delete", post(self::post::delete_url))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    check_user_url_access,
                )),
        )
}

async fn check_user_url_access(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(url_id): Path<String>,
    req: Request,
    next: Next,
) -> AppResult<Response> {
    let Some(user) = auth_session.user else {
        return Err(AppError::Unauthorized);
    };

    match state.repo.get_url_by_id(&url_id).await {
        Ok(ShortenedUrl { user_id, .. }) if user.id() == user_id => Ok(next.run(req).await),
        Ok(_) => Err(AppError::Unauthorized),
        Err(sqlx::Error::RowNotFound) => Err(AppError::UrlNotFound),
        Err(e) => {
            error!("error while checking user access to url: {}", e);
            Err(AppError::InternalServerError)
        }
    }
}

mod get {
    use super::*;

    pub async fn protected(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user {
            Some(user) => ProtectedTemplate {
                username: &user.username,
            }
            .into_response(),

            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    pub async fn shorten() -> impl IntoResponse {
        ShortenUrlTemplate {
            initial_url: "",
            shortened_url: None,
            error_message: None,
        }
        .into_response()
    }

    pub async fn list_urls(
        State(state): State<AppState>,
        Query(DeleteResult { delete_success }): Query<DeleteResult>,
        auth_session: AuthSession,
    ) -> impl IntoResponse {
        let Some(user) = auth_session.user else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        match state.repo.get_all_urls(user.id()).await {
            Ok(mut urls) => {
                urls.retain(|url| !url.deleted);

                let success_message = if delete_success == Some(true) {
                    Some("URL successfully deleted.")
                } else {
                    None
                };

                let error_message = if delete_success == Some(false) {
                    Some("Failed to delete URL.")
                } else {
                    None
                };

                UrlListTemplate {
                    shortened_url_base: state.shortened_url_base.as_ref(),
                    active_urls: &urls,
                    error_message,
                    success_message,
                }
            }
            .into_response(),
            Err(e) => {
                error!("Failed to get URLs: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }

    pub async fn url_details(
        State(state): State<AppState>,
        Path(url_id): Path<String>,
    ) -> impl IntoResponse {
        match try_join!(
            state.repo.get_url_by_id(&url_id),
            state.repo.get_url_redirect_statistic(&url_id)
        ) {
            Ok((ref url, ref statistic)) => UrlDetailsTemplate {
                shortened_url_base: state.shortened_url_base.as_ref(),
                url,
                statistic,
            }
            .into_response(),
            Err(e) => {
                error!("Failed to get URL: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

mod post {
    use axum::response::Redirect;

    use super::*;

    // TODO: CSRF protection
    pub async fn shorten(
        State(state): State<AppState>,
        auth_session: AuthSession,
        Form(ShortenUrl { url }): Form<ShortenUrl>,
    ) -> impl IntoResponse {
        let Some(user) = auth_session.user else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        if let Err(e) = reqwest::Url::parse(&url) {
            return ShortenUrlTemplate {
                initial_url: &url,
                shortened_url: None,
                error_message: Some(&format!("Invalid URL: {}", e)),
            }
            .into_response();
        }

        match state.repo.create_url(user.id(), &url).await {
            Ok(shortened_url) => ShortenUrlTemplate {
                initial_url: "",
                shortened_url: Some(&format!(
                    "{}{}",
                    state.shortened_url_base, &shortened_url.id
                )),
                error_message: None,
            }
            .into_response(),
            Err(e) => {
                error!("Failed to create URL: {}", e);
                ShortenUrlTemplate {
                    initial_url: &url,
                    shortened_url: None,
                    error_message: Some("Failed to create URL."),
                }
                .into_response()
            }
        }
    }

    // TODO: CSRF protection
    pub async fn delete_url(
        State(state): State<AppState>,
        Path(url_id): Path<String>,
    ) -> impl IntoResponse {
        match state.repo.delete_url_by_id(&url_id).await {
            Ok(_) => Redirect::to("/urls?delete_success=true"),
            Err(e) => {
                error!("Failed to delete URL: {}", e);
                Redirect::to("/urls?delete_success=false")
            }
        }
    }
}
