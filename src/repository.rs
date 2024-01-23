use nanoid::nanoid;
use sqlx::FromRow;
use tokio::try_join;
use tracing::log::warn;

use crate::users::{AppUserId, GithubUserInfo, User};

#[derive(Debug, Clone, serde::Serialize, FromRow)]
pub struct ShortenedUrl {
    pub id: String,
    pub location: String,
    pub deleted: bool,
    pub user_id: AppUserId,
}

pub struct RedirectStatistic {
    pub total_clicks: i64,
    pub day_statistic: Vec<RedirectStatisticEntry>,
}

#[derive(Debug, Clone, serde::Serialize, FromRow)]
pub struct RedirectStatisticEntry {
    pub bucket: String,
    pub clicks: i64,
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
    ) -> Result<User, sqlx::Error> {
        const QUERY: &str = r#"
            INSERT INTO
                users (id, username, avatar_url, github_token)
            VALUES
                ($1, $2, $3, $4)
            ON CONFLICT (id) DO UPDATE SET
                username = EXCLUDED.username,
                avatar_url = EXCLUDED.avatar_url,
                github_token = EXCLUDED.github_token
            RETURNING
                id, username, avatar_url, github_token
        "#;

        sqlx::query_as(QUERY)
            .bind(user_info.id)
            .bind(&user_info.login)
            .bind(&user_info.avatar_url)
            .bind(github_token)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_user_by_id(&self, id: AppUserId) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as("SELECT id, username, avatar_url, github_token FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn get_url_by_id(&self, url_id: &str) -> Result<ShortenedUrl, sqlx::Error> {
        sqlx::query_as("SELECT id, location, deleted, user_id FROM shortened_urls WHERE id = $1")
            .bind(url_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_all_urls(&self, user_id: AppUserId) -> Result<Vec<ShortenedUrl>, sqlx::Error> {
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
        user_id: AppUserId,
        location: &str,
    ) -> Result<ShortenedUrl, sqlx::Error> {
        const QUERY: &str = r#"
            INSERT INTO
                shortened_urls (id, location, user_id)
            VALUES
                ($1, $2, $3)
            RETURNING
                id, location, deleted, user_id
        "#;

        // TODO: Try again on id conflict
        let url_id = nanoid!(10);
        sqlx::query_as(QUERY)
            .bind(url_id)
            .bind(location)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_url_redirect_statistic(
        &self,
        url_id: &str,
    ) -> Result<RedirectStatistic, sqlx::Error> {
        const QUERY_PER_HOUR: &str = r#"
            SELECT
                CAST(date_trunc('second', time_series) AS TEXT) AS bucket,
                COUNT(r.*) AS clicks
            FROM
                generate_series(
                    date_trunc('hour', now()) - '1 day'::interval,
                    date_trunc('hour', now() - '1 hour'::interval),
                    '1 hour'::interval
                ) AS time_series
            LEFT JOIN
                redirects r ON time_series = time_bucket('1 hour', r.time)
                    AND url_id = $1  -- Don't use `where` so that we keep empty buckets
            GROUP BY
                bucket
            ORDER BY
                bucket
        "#;

        const QUERY_TOTAL: &str = r#"
            SELECT
                COUNT(*) AS clicks
            FROM
                redirects
            WHERE
                url_id = $1
        "#;

        let day_statistic_future = sqlx::query_as(QUERY_PER_HOUR)
            .bind(url_id)
            .fetch_all(&self.pool);

        let total_clicks_future = sqlx::query_scalar(QUERY_TOTAL)
            .bind(url_id)
            .fetch_one(&self.pool);

        match try_join!(day_statistic_future, total_clicks_future) {
            Ok((day_statistic, total_clicks)) => Ok(RedirectStatistic {
                total_clicks,
                day_statistic,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn delete_url_by_id(&self, id: &str) -> Result<ShortenedUrl, sqlx::Error> {
        sqlx::query_as("UPDATE shortened_urls SET deleted = TRUE WHERE id = $1 RETURNING id, location, deleted, user_id")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }
}
