use std::{collections::HashSet, env, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, TokenResponse, TokenUrl,
};
use rand::RngCore;
use reqwest::header::{HeaderMap, USER_AGENT};
use sha2::Digest;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Mutex;
use tracing::error;

use super::error::{AppError, AppResult};
use crate::repository::{GithubUserInfo, RedirectStatisticEntry, Repository, ShortenedUrl, UserId};

pub struct App {
    state: AppState,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // We don't care whether we get the environment variables via a .env file
        let _ = dotenvy::dotenv();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        // TODO: What pool size is optimal?
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await?;

        let repo = Repository::new(pool);

        let github_oauth_client = create_github_oauth_client()?;

        let state = AppState::new(repo, github_oauth_client);
        Ok(Self { state })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .nest("/api", make_api_router(self.state.clone()))
            .route("/:url_id", get(redirect))
            .with_state(self.state);

        let addr = SocketAddr::from(([127, 0, 0, 1], 7208));
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AppState {
    repo: Repository,
    github_oauth_client: Arc<BasicClient>,
    github_csrf_states: Arc<Mutex<HashSet<String>>>,
}

impl AppState {
    fn new(repo: Repository, github_oauth_client: BasicClient) -> Self {
        AppState {
            repo,
            github_oauth_client: Arc::new(github_oauth_client),
            github_csrf_states: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GithubCallbackParams {
    code: String,
    state: String,
}

#[derive(serde::Deserialize)]
struct ShortenUrl {
    location: String,
}

#[derive(Debug, Clone)]
struct CurrentUser {
    id: UserId,
}

fn create_github_oauth_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let github_client_id =
        ClientId::new(env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID must be set"));
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET must be set"),
    );
    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap();
    let token_url =
        TokenUrl::new("https:/github.com/login/oauth/access_token".to_string()).unwrap();

    let redirect_path = "/api/auth/github/callback";
    let redirect_uri = RedirectUrl::new(if cfg!(debug_assertions) {
        format!("http://127.0.0.1:7208{}", redirect_path)
    } else {
        env::var("PUBLIC_BASE_URL").expect("PUBLIC_BASE_URL must be set") + redirect_path
    })?;

    let client = BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_uri);

    Ok(client)
}

fn make_api_router(state: AppState) -> Router<AppState> {
    let auth_router = Router::new()
        .route("/github/login", get(github_login))
        .route("/github/callback", get(github_callback));

    let url_router = Router::new()
        .route("/", get(get_all_urls))
        .route("/", post(shorten))
        .nest(
            "/:id",
            Router::new()
                .route("/", get(get_url))
                .route("/", delete(delete_url))
                .route("/redirect-statistic", get(redirect_statistic))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    check_user_url_access,
                )),
        )
        .route_layer(middleware::from_fn_with_state(state, authenticate_user));

    Router::new()
        .nest("/auth", auth_router)
        .nest("/url", url_router)
}

async fn check_user_url_access(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(url_id): Path<String>,
    req: Request,
    next: Next,
) -> AppResult<Response> {
    match state.repo.get_url_by_id(&url_id).await {
        Ok(ShortenedUrl { user_id, .. }) if user.id == user_id => Ok(next.run(req).await),
        Ok(_) => Err(AppError::Unauthorized),
        Err(sqlx::Error::RowNotFound) => Err(AppError::UrlNotFound),
        Err(e) => {
            error!("error while checking user access to url: {}", e);
            Err(AppError::InternalServerError)
        }
    }
}

async fn authenticate_user(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> AppResult<Response> {
    let session_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(AppError::NotLoggedIn)?
        .to_str()
        .map_err(|_| AppError::InvalidAuthorizationHeader)?
        .strip_prefix("Bearer ")
        .ok_or(AppError::InvalidAuthorizationHeader)?;

    if session_token.is_empty() {
        return Err(AppError::InvalidAuthorizationHeader);
    }

    let hashed_session_token = hash_session_token(session_token);
    let user_id = state
        .repo
        .get_user_id_by_session_token(&hashed_session_token)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::SessionExpired,
            _ => {
                error!("error while getting user by session token: {}", e);
                AppError::InternalServerError
            }
        })?;

    req.extensions_mut().insert(CurrentUser { id: user_id });

    Ok(next.run(req).await)
}

fn get_random_bytes<const L: usize>() -> [u8; L] {
    let mut bytes = [0; L];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn hash_session_token(token: &str) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    hasher.finalize().to_vec()
}

fn generate_session_token() -> (String, Vec<u8>) {
    let token_bytes = get_random_bytes::<32>();
    let token = general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
    let hashed_token = hash_session_token(&token);
    (token, hashed_token)
}

async fn redirect(Path(url_id): Path<String>, State(state): State<AppState>) -> Response {
    match state.repo.redirect_by_url_id(&url_id).await {
        Ok(ShortenedUrl { ref location, .. }) => (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, location)],
            Html(format!(r#"Your link is <a href="{}">here</a>"#, location)),
        )
            .into_response(),
        Err(sqlx::Error::RowNotFound) => (
            StatusCode::NOT_FOUND,
            Html("This link does not exist or was deleted".to_string()),
        )
            .into_response(),
        Err(e) => {
            error!("error while redirecting: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Internal server error".to_string()),
            )
                .into_response()
        }
    }
}

async fn github_login(State(state): State<AppState>) -> AppResult<Response> {
    let (authorize_url, csrf_state) = state
        .github_oauth_client
        .authorize_url(CsrfToken::new_random)
        .url();

    state
        .github_csrf_states
        .lock()
        .await
        .insert(csrf_state.secret().clone());

    let response = (
        StatusCode::FOUND,
        [(header::LOCATION, authorize_url.to_string())],
        Html(format!(
            r#"Follow <a href="{}">this link</a> to log in via GitHub"#,
            authorize_url
        )),
    )
        .into_response();

    Ok(response)
}

async fn github_callback(
    State(app_state): State<AppState>,
    Query(params): Query<GithubCallbackParams>,
) -> AppResult<Response> {
    {
        if !app_state
            .github_csrf_states
            .lock()
            .await
            .remove(&params.state)
        {
            return Err(AppError::BadRequest("Invalid CSRF state".to_string()));
        }
    }

    let code = AuthorizationCode::new(params.code);

    let token = app_state
        .github_oauth_client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            error!("error while exchanging github code: {}", err);
            AppError::InternalServerError
        })?;

    let access_token = token.access_token();

    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, "reqwest".parse().unwrap());

    let github_user_info: GithubUserInfo = client
        .get("https://api.github.com/user")
        .headers(headers)
        .bearer_auth(access_token.secret())
        .send()
        .await
        .map_err(|err| {
            error!("error while getting github user info: {}", err);
            AppError::InternalServerError
        })?
        .json()
        .await
        .map_err(|err| {
            error!("error while parsing github user info: {}", err);
            AppError::InternalServerError
        })?;

    app_state
        .repo
        .upsert_user(&github_user_info, access_token.secret())
        .await
        .map_err(|e| {
            error!("error while upserting user: {}", e);
            AppError::InternalServerError
        })?;

    let (session_token, hashed_session_token) = generate_session_token();

    app_state
        .repo
        .create_session(github_user_info.id, &hashed_session_token)
        .await
        .map_err(|e| {
            error!("error while creating session: {}", e);
            AppError::InternalServerError
        })?;

    // TODO: Create better response: Redirect to frontend with token in query param, also add token
    // in header for headless clients

    let response = Html(format!(
        "Successfully logged in via GitHub! Your GitHub user id is: {}. Your session token is: {}",
        github_user_info.id, session_token
    ))
    .into_response();

    Ok(response)
}

async fn get_all_urls(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> AppResult<Json<Vec<ShortenedUrl>>> {
    state
        .repo
        .get_all_urls(user.id)
        .await
        .map(Json)
        .map_err(|e| {
            error!("error while getting all urls: {}", e);
            AppError::InternalServerError
        })
}

async fn shorten(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(payload): Json<ShortenUrl>,
) -> AppResult<Json<ShortenedUrl>> {
    if reqwest::Url::parse(&payload.location).is_err() {
        return Err(AppError::BadRequest("Invalid URL".to_string()));
    }

    state
        .repo
        .create_url(user.id, &payload.location)
        .await
        .map(Json)
        .map_err(|e| {
            error!("error while shortening url: {}", e);
            AppError::InternalServerError
        })
}

async fn get_url(
    Path(url_id): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Json<ShortenedUrl>> {
    state
        .repo
        .get_url_by_id(&url_id)
        .await
        .map(Json)
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::UrlNotFound,
            _ => {
                error!("error while getting url: {}", e);
                AppError::InternalServerError
            }
        })
}

async fn delete_url(
    Path(url_id): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Json<ShortenedUrl>> {
    state
        .repo
        .delete_url_by_id(&url_id)
        .await
        .map(Json)
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::UrlNotFound,
            _ => {
                error!("error while deleting url: {}", e);
                AppError::InternalServerError
            }
        })
}

async fn redirect_statistic(
    Path(url_id): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<RedirectStatisticEntry>>> {
    state
        .repo
        .get_url_redirect_statistic(&url_id)
        .await
        .map(Json)
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::UrlNotFound,
            _ => {
                error!("error while getting url redirect statistic: {}", e);
                AppError::InternalServerError
            }
        })
}
