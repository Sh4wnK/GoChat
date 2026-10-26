-- GoChat schema, applied in order by the embedded migrator.
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password     TEXT NOT NULL,
    public_key   TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_username_idx ON users (username);

CREATE TABLE IF NOT EXISTS offline_messages (
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    message_id   TEXT NOT NULL,
    payload      TEXT NOT NULL,
    queued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, message_id)
);

CREATE INDEX IF NOT EXISTS offline_messages_user_idx ON offline_messages (user_id, queued_at);
