PRAGMA foreign_keys = ON;

BEGIN;

CREATE TABLE people (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    breach_count INTEGER CHECK (breach_count >= 0),
    latest_breach_name TEXT CHECK (length(trim(latest_breach_name)) > 0),
    latest_breach_on TEXT CHECK (date(latest_breach_on, '+0 days') IS latest_breach_on),
    passwords_involved INTEGER CHECK (passwords_involved IN (0, 1)),
    breach_checked_on TEXT CHECK (date(breach_checked_on, '+0 days') IS breach_checked_on),
    CHECK (breach_checked_on IS NOT NULL OR
           (breach_count IS NULL AND latest_breach_name IS NULL AND latest_breach_on IS NULL
            AND passwords_involved IS NULL)),
    CHECK (latest_breach_on <= breach_checked_on),
    CHECK (breach_count != 0 OR
           (latest_breach_name IS NULL AND latest_breach_on IS NULL AND passwords_involved IS NOT 1))
) STRICT;

CREATE TABLE controls (
    person_id INTEGER NOT NULL REFERENCES people(id),
    control TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in place', 'missing', 'unknown')),
    checked_on TEXT CHECK (date(checked_on, '+0 days') IS checked_on),
    CHECK (status = 'unknown' OR checked_on IS NOT NULL),
    PRIMARY KEY (person_id, control)
) STRICT;

CREATE TABLE device_owners (
    person_id INTEGER NOT NULL REFERENCES people(id),
    source TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    label TEXT NOT NULL CHECK (length(trim(label)) > 0),
    PRIMARY KEY (person_id, source, source_ref)
) STRICT;

CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0)
) STRICT;

CREATE TABLE service_accounts (
    person_id INTEGER NOT NULL REFERENCES people(id),
    service_id INTEGER NOT NULL REFERENCES services(id),
    PRIMARY KEY (person_id, service_id)
) STRICT;

CREATE INDEX idx_service_accounts_service_id ON service_accounts(service_id);

CREATE TABLE crypto_accounts (
    person_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    mfa_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (mfa_status IN ('in place', 'missing', 'unknown')),
    mfa_checked_on TEXT CHECK (date(mfa_checked_on, '+0 days') IS mfa_checked_on),
    withdrawal_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (withdrawal_status IN ('in place', 'missing', 'unknown', 'not offered')),
    withdrawal_checked_on TEXT
        CHECK (date(withdrawal_checked_on, '+0 days') IS withdrawal_checked_on),
    CHECK (mfa_status = 'unknown' OR mfa_checked_on IS NOT NULL),
    CHECK (withdrawal_status = 'unknown' OR withdrawal_checked_on IS NOT NULL),
    PRIMARY KEY (person_id, service_id),
    FOREIGN KEY (person_id, service_id) REFERENCES service_accounts(person_id, service_id)
) STRICT;

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('breach', 'vendor')),
    service_id INTEGER REFERENCES services(id),
    person_id INTEGER REFERENCES people(id),
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    reported_on TEXT NOT NULL CHECK (date(reported_on, '+0 days') IS reported_on),
    state TEXT NOT NULL CHECK (state IN ('open', 'done', 'dismissed')),
    state_checked_on TEXT NOT NULL CHECK (date(state_checked_on, '+0 days') IS state_checked_on),
    CHECK (state_checked_on >= reported_on),
    CHECK ((kind = 'breach' AND person_id IS NOT NULL) OR
           (kind = 'vendor' AND service_id IS NOT NULL AND person_id IS NULL))
) STRICT;

COMMIT;
