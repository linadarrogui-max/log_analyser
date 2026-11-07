CREATE TABLE IF NOT EXISTS ip_country_ranges (
    network CIDR PRIMARY KEY,
    country TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authentication_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_file TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    month TEXT NOT NULL,
    day SMALLINT NOT NULL CHECK (day BETWEEN 1 AND 31),
    log_time TIME NOT NULL,
    host TEXT NOT NULL,
    process TEXT NOT NULL,
    username TEXT NOT NULL,
    ip_address INET NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('failed', 'successful')),
    invalid_user BOOLEAN NOT NULL DEFAULT FALSE,
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    country TEXT NOT NULL DEFAULT 'Inconnu',
    message TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_file, line_number)
);

CREATE INDEX IF NOT EXISTS idx_authentication_events_status
    ON authentication_events (status);
CREATE INDEX IF NOT EXISTS idx_authentication_events_username
    ON authentication_events (username);
CREATE INDEX IF NOT EXISTS idx_authentication_events_country
    ON authentication_events (country);
CREATE INDEX IF NOT EXISTS idx_authentication_events_ip
    ON authentication_events (ip_address);
