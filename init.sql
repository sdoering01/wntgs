CREATE EXTENSION IF NOT EXISTS timescaledb;

DROP TABLE IF EXISTS redirects_hourly;
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
    deleted BOOL NOT NULL DEFAULT FALSE,
    user_id INT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX ix_shortened_urls_user_id ON shortened_urls (user_id);

CREATE TABLE redirects (
    time TIMESTAMPTZ NOT NULL,
    url_id TEXT NOT NULL REFERENCES shortened_urls(id) ON DELETE CASCADE
);
SELECT create_hypertable('redirects', by_range('time'));
CREATE INDEX ix_time_urlid ON redirects (url_id, time DESC);
