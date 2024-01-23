use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    error_handling::HandleErrorLayer,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    BoxError,
};
use axum_login::{login_required, AuthManagerLayerBuilder};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::postgres::PgPoolOptions;
use time::Duration;
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::SameSite, Expiry, PostgresStore, SessionManagerLayer};
use tracing::error;

use crate::{
    repository::{Repository, ShortenedUrl},
    users::Backend,
    web::{auth, oauth, protected},
};

pub const URL_REDIRECT_PREFIX: &str = "/u/";

pub struct App {
    state: AppState,
    session_store: PostgresStore,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // We don't care whether we get the environment variables via a .env file
        let _ = dotenvy::dotenv();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let public_base_url = env::var("PUBLIC_BASE_URL").expect("PUBLIC_BASE_URL must be set");

        // TODO: What pool size is optimal?
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await?;

        let repo = Repository::new(pool.clone());

        let github_oauth_client = create_github_oauth_client()?;

        let session_store = PostgresStore::new(pool);
        session_store.migrate().await?;

        let state = AppState::new(repo, github_oauth_client, public_base_url);
        Ok(Self {
            state,
            session_store,
        })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let session_layer = SessionManagerLayer::new(self.session_store)
            .with_secure(!cfg!(debug_assertions))
            // Required to send cookie on OAuth redirect
            .with_same_site(SameSite::Lax)
            .with_expiry(Expiry::OnInactivity(Duration::days(1)));

        let backend = Backend::new(
            self.state.repo.clone(),
            self.state.github_oauth_client.as_ref().clone(),
        );
        let auth_service = ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async {
                StatusCode::BAD_REQUEST
            }))
            .layer(AuthManagerLayerBuilder::new(backend, session_layer).build());

        let app = protected::router(self.state.clone())
            .route_layer(login_required!(Backend, login_url = "/login"))
            .merge(auth::router())
            .merge(oauth::router())
            .route("/u/:url_id", get(redirect))
            .layer(auth_service)
            .nest_service("/static", ServeDir::new("static"))
            .with_state(self.state);

        let addr = SocketAddr::from(([127, 0, 0, 1], 7208));
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub repo: Repository,
    pub github_oauth_client: Arc<BasicClient>,
    pub shortened_url_base: Arc<str>,
}

impl AppState {
    fn new(
        repo: Repository,
        github_oauth_client: BasicClient,
        public_base_url: impl Into<String>,
    ) -> Self {
        AppState {
            repo,
            github_oauth_client: Arc::new(github_oauth_client),
            shortened_url_base: Arc::from(public_base_url.into() + URL_REDIRECT_PREFIX),
        }
    }
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

    let redirect_path = "/oauth/github/callback";
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
