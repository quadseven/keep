PRAGMA foreign_keys = ON;

BEGIN;

CREATE TABLE people (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    breach_count INTEGER CHECK (breach_count >= 0),
    latest_breach_on TEXT CHECK (date(latest_breach_on, '+0 days') IS latest_breach_on),
    passwords_involved INTEGER CHECK (passwords_involved IN (0, 1)),
    breach_checked_on TEXT CHECK (date(breach_checked_on, '+0 days') IS breach_checked_on),
    CHECK (breach_checked_on IS NOT NULL OR
           (breach_count IS NULL AND latest_breach_on IS NULL AND passwords_involved IS NULL)),
    CHECK (latest_breach_on <= breach_checked_on),
    CHECK (breach_count != 0 OR (latest_breach_on IS NULL AND passwords_involved IS NOT 1))
) STRICT;

CREATE TABLE controls (
    person_id INTEGER NOT NULL REFERENCES people(id),
    control TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in place', 'missing', 'unknown')),
    checked_on TEXT CHECK (date(checked_on, '+0 days') IS checked_on),
    CHECK (status = 'unknown' OR checked_on IS NOT NULL),
    PRIMARY KEY (person_id, control)
) STRICT;

COMMIT;
