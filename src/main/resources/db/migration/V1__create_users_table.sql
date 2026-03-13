CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN
CREATE TYPE user_role AS ENUM ('ADMIN', 'READER');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS users (
                                     id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(120)  NOT NULL,
    email           VARCHAR(254)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255),
    oauth_provider  VARCHAR(32),
    oauth_sub       VARCHAR(255),
    role            user_role     NOT NULL DEFAULT 'READER',
    is_active       BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_users_email
    ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_oauth
    ON users(oauth_provider, oauth_sub);

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();