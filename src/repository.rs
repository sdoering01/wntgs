use nanoid::nanoid;
use sqlx::FromRow;
use tracing::log::warn;

const QUERY_GET_URL_STATISTICS: &str = "\
SELECT
    CAST(date_trunc('second', time_series) AS TEXT) AS bucket,
    COUNT(r.*) AS count
FROM
    generate_series(
        date_trunc('hour', now()) - INTERVAL '1 days',
        date_trunc('hour', now()),
        '1 hour'::interval
    ) AS time_series
LEFT JOIN
    redirects r ON time_series = time_bucket('1 hour', r.time)
        AND url_id = $1  -- Don't use `where` so that we keep empty buckets
GROUP BY
    bucket
ORDER BY
    bucket";

pub type UserId = i32;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GithubUserInfo {
    pub id: UserId,
    pub login: String,
    pub avatar_url: String,
}

#[derive(Debug, Clone, serde::Serialize, FromRow)]
pub struct ShortenedUrl {
    pub id: String,
    pub location: String,
    pub deleted: bool,
    pub user_id: UserId,
}

#[derive(Debug, Clone, serde::Serialize, FromRow)]
pub struct RedirectStatisticEntry {
    pub bucket: String,
    pub count: i64,
}

#[derive(Debug, Clone)]
pub struct Repository {
    pool: sqlx::PgPool,
}

impl Repository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Repository { pool }
    }

    pub async fn upsert_user(
        &self,
        user_info: &GithubUserInfo,
        github_token: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO users (id, name, avatar_url, github_token) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET name = $2, avatar_url = $3, github_token = $4")
            .bind(user_info.id)
            .bind(&user_info.login)
            .bind(&user_info.avatar_url)
            .bind(github_token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn create_session(
        &self,
        user_id: UserId,
        hashed_session_token: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO user_sessions (user_id, hashed_token) VALUES ($1, $2)")
            .bind(user_id)
            .bind(hashed_session_token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_user_id_by_session_token(
        &self,
        hashed_session_token: &[u8],
    ) -> Result<UserId, sqlx::Error> {
        sqlx::query_scalar("SELECT user_id FROM user_sessions WHERE hashed_token = $1")
            .bind(hashed_session_token)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_url_by_id(&self, url_id: &str) -> Result<ShortenedUrl, sqlx::Error> {
        sqlx::query_as("SELECT id, location, deleted, user_id FROM shortened_urls WHERE id = $1")
            .bind(url_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_all_urls(&self, user_id: UserId) -> Result<Vec<ShortenedUrl>, sqlx::Error> {
        sqlx::query_as(
            "SELECT id, location, deleted, user_id FROM shortened_urls WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn redirect_by_url_id(&self, id: &str) -> Result<ShortenedUrl, sqlx::Error> {
        let maybe_shortened_url = sqlx::query_as(
            "SELECT id, location, deleted, user_id FROM shortened_urls WHERE id = $1 AND deleted = FALSE",
        ).bind(id).fetch_one(&self.pool).await;

        if maybe_shortened_url.is_ok() {
            if let Err(e) = sqlx::query("INSERT INTO redirects(time, url_id) VALUES (now(), $1)")
                .bind(id)
                .execute(&self.pool)
                .await
            {
                warn!("error while inserting redirect: {}", e);
            }
        }
        maybe_shortened_url
    }

    pub async fn create_url(
        &self,
        user_id: UserId,
        location: &str,
    ) -> Result<ShortenedUrl, sqlx::Error> {
        // TODO: Try again on id conflict
        let url_id = nanoid!(10);
        sqlx::query_as(
            "INSERT INTO shortened_urls (id, location, user_id) VALUES ($1, $2, $3) RETURNING id, location, deleted, user_id",
        )
        .bind(url_id)
        .bind(location)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_url_redirect_statistic(
        &self,
        url_id: &str,
    ) -> Result<Vec<RedirectStatisticEntry>, sqlx::Error> {
        sqlx::query_as(QUERY_GET_URL_STATISTICS)
            .bind(url_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn delete_url_by_id(&self, id: &str) -> Result<ShortenedUrl, sqlx::Error> {
        sqlx::query_as("UPDATE shortened_urls SET deleted = TRUE WHERE id = $1 RETURNING id, location, deleted, user_id")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }
}
