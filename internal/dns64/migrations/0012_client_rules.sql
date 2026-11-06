-- Antwortregeln nach Clientnetz (DNS64), optional nur auf der eigenen Node.
CREATE TABLE dns64_client_rules (
    id         INTEGER PRIMARY KEY,
    network    TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    a          TEXT    NOT NULL DEFAULT '',
    aaaa       TEXT    NOT NULL DEFAULT '',
    ttl        INTEGER NOT NULL DEFAULT 300,
    comment    TEXT    NOT NULL DEFAULT '',
    local_only INTEGER NOT NULL DEFAULT 0,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    UNIQUE (network, name)
);
CREATE INDEX dns64_client_rules_name ON dns64_client_rules(name, enabled);
