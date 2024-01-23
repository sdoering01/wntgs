CREATE EXTENSION IF NOT EXISTS timescaledb;


DROP MATERIALIZED VIEW IF EXISTS redirects_hourly;
DROP TABLE IF EXISTS redirects;
DROP TABLE IF EXISTS shortened_urls;
DROP TABLE IF EXISTS users;


CREATE TABLE users (
    id INT PRIMARY KEY,
    username TEXT NOT NULL,
    avatar_url TEXT NOT NULL,
    github_token TEXT NOT NULL
);


CREATE TABLE shortened_urls (
    id TEXT PRIMARY KEY,
    location TEXT NOT NULL,
    total_clicks BIGINT NOT NULL DEFAULT 0,
    deleted BOOL NOT NULL DEFAULT FALSE,
    user_id INT REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX ix_shortened_urls_user_id ON shortened_urls (user_id);


CREATE TABLE redirects (
    time TIMESTAMPTZ NOT NULL,
    url_id TEXT NOT NULL REFERENCES shortened_urls(id) ON DELETE CASCADE
);

SELECT create_hypertable('redirects', by_range('time'));

-- Be careful to not set this shorter than the continuous aggregate policy's
-- start_offset!
SELECT add_retention_policy('redirects', drop_after => '12 hours'::INTERVAL);


CREATE MATERIALIZED VIEW redirects_hourly WITH (timescaledb.continuous) AS
    SELECT
        time_bucket('1 hour', time) AS hour,
        url_id,
        count(*) AS clicks
    FROM
        redirects
    GROUP BY
        hour, url_id;

CREATE INDEX ix_redirects_hourly_hour_urlid ON redirects_hourly (url_id, hour DESC);

SELECT add_continuous_aggregate_policy('redirects_hourly',
    start_offset => '2h30m'::INTERVAL,
    end_offset => '30m'::INTERVAL,
    schedule_interval => '30m'::INTERVAL);

SELECT add_retention_policy('redirects_hourly', drop_after => '7 days'::INTERVAL);
