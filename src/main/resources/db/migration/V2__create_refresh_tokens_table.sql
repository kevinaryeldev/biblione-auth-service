CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255)  NOT NULL,
    expires_at  TIMESTAMPTZ   NOT NULL,
    revoked_at  TIMESTAMPTZ,
    ip_address  INET,
    user_agent  VARCHAR(512),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_refresh_user_id
    ON refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_token_hash
    ON refresh_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_refresh_expires_at
    ON refresh_tokens(expires_at);