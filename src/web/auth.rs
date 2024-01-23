use askama::Template;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use axum_login::tower_sessions::Session;

use crate::{
    users::AuthSession,
    web::{app::AppState, oauth::GITHUB_CSRF_STATE_KEY},
};

pub const NEXT_URL_KEY: &str = "auth.next-url";

#[derive(Template)]
#[template(path = "unprotected/login.html")]
pub struct LoginTemplate {
    pub message: Option<String>,
    pub next: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(self::post::login))
        .route("/login", get(self::get::login))
        .route("/logout", get(self::get::logout))
}

mod post {
    use super::*;

    pub async fn login(
        auth_session: AuthSession,
        session: Session,
        Form(NextUrl { next }): Form<NextUrl>,
    ) -> impl IntoResponse {
        let (auth_url, csrf_state) = auth_session.backend.github_authorize_url();

        session
            .insert(GITHUB_CSRF_STATE_KEY, csrf_state.secret())
            .await
            .expect("Serialization should not fail.");

        session
            .insert(NEXT_URL_KEY, next)
            .await
            .expect("Serialization should not fail.");

        Redirect::to(auth_url.as_str()).into_response()
    }
}

mod get {
    use super::*;

    pub async fn login(
        auth_session: AuthSession,
        Query(NextUrl { next }): Query<NextUrl>,
    ) -> impl IntoResponse {
        if auth_session.user.is_none() {
            LoginTemplate {
                message: None,
                next,
            }
            .into_response()
        } else {
            Redirect::to("/").into_response()
        }
    }

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
