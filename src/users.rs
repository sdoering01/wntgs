use async_trait::async_trait;
use axum::http::header::USER_AGENT;
use axum_login::{AuthUser, AuthnBackend, UserId};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    url::Url,
    AuthorizationCode, CsrfToken, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::repository::Repository;

pub type AppUserId = i32;

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: AppUserId,
    pub username: String,
    pub avatar_url: String,
    pub github_token: String,
}

// Manually implement `Debug` to avoid leaking the access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("avatar_url", &self.avatar_url)
            .field("github_token", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = AppUserId;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.github_token.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubCredentials {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Deserialize)]
pub struct GithubUserInfo {
    pub id: AppUserId,
    pub login: String,
    pub avatar_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),
}

#[derive(Debug, Clone)]
pub struct Backend {
    repository: Repository,
    github_client: BasicClient,
}

impl Backend {
    pub fn new(repository: Repository, client: BasicClient) -> Self {
        Self {
            repository,
            github_client: client,
        }
    }

    pub fn github_authorize_url(&self) -> (Url, CsrfToken) {
        self.github_client
            .authorize_url(CsrfToken::new_random)
            .url()
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = GithubCredentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Ensure the CSRF state has not been tampered with.
        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Process authorization code, expecting a token response back.
        let token_res = self
            .github_client
            .exchange_code(AuthorizationCode::new(creds.code))
            .request_async(async_http_client)
            .await
            .map_err(Self::Error::OAuth2)?;

        let github_token = token_res.access_token().secret();

        // Use access token to request user info.
        let user_info = reqwest::Client::new()
            .get("https://api.github.com/user")
            .header(USER_AGENT.as_str(), "reqwest")
            .bearer_auth(token_res.access_token().secret())
            .send()
            .await
            .map_err(Self::Error::Reqwest)?
            .json::<GithubUserInfo>()
            .await
            .map_err(Self::Error::Reqwest)?;

        // Persist user in our database so we can use `get_user`.
        let user = self
            .repository
            .upsert_user(&user_info, github_token.as_str())
            .await
            .map_err(Self::Error::Sqlx)?;

        Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        self.repository
            .get_user_by_id(*user_id)
            .await
            .map_err(Self::Error::Sqlx)
    }
}

pub type AuthSession = axum_login::AuthSession<Backend>;
