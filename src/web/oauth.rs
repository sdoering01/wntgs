use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_login::tower_sessions::Session;
use oauth2::CsrfToken;

use crate::{
    users::{AuthSession, GithubCredentials},
    web::{
        app::AppState,
        auth::{LoginTemplate, NEXT_URL_KEY},
    },
};

pub const GITHUB_CSRF_STATE_KEY: &str = "oauth.github.csrf-state";

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthzResp {
    code: String,
    state: CsrfToken,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/oauth/github/callback", get(self::get::github_callback))
}

mod get {
    use super::*;

    pub async fn github_callback(
        mut auth_session: AuthSession,
        session: Session,
        Query(AuthzResp {
            code,
            state: new_state,
        }): Query<AuthzResp>,
    ) -> impl IntoResponse {
        let Ok(Some(old_state)) = session.get(GITHUB_CSRF_STATE_KEY).await else {
            return StatusCode::BAD_REQUEST.into_response();
        };

        let creds = GithubCredentials {
            code,
            old_state,
            new_state,
        };

        let user = match auth_session.authenticate(creds).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    LoginTemplate {
                        message: Some("Invalid CSRF state.".to_string()),
                        next: None,
                    },
                )
                    .into_response()
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        if auth_session.login(&user).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        if let Ok(Some(next)) = session.remove::<String>(NEXT_URL_KEY).await {
            // Only allows relative redirects, but not protocol-relative redirects.
            // This prevents open redirects.
            if next.starts_with('/') && !next.starts_with("//") {
                return Redirect::to(&next).into_response();
            }
        };

        Redirect::to("/").into_response()
    }
}
