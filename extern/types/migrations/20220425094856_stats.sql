-- Add migration script here
CREATE TABLE IF NOT EXISTS stats
(
    addr          TEXT                NOT NULL,
    backend       TEXT                NOT NULL,
    named         TEXT                NOT NULL,
    tag           TEXT                NOT NULL,
    chain_id      INTEGER DEFAULT 0   NOT NULL,
    latest        INTEGER DEFAULT 0   NOT NULL,
    disused       BOOLEAN DEFAULT 0   NOT NULL,
    primary key   (chain_id,addr)
);

CREATE INDEX index_stats on stats (chain_id, addr);