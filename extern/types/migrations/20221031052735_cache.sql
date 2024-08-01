-- Add migration script here
CREATE TABLE IF NOT EXISTS cache
(
    tstamp                INTEGER            NOT NULL,
    src_chain_id          INTEGER            NOT NULL,
    dst_chain_id          INTEGER            NOT NULL,
    src_hash              TEXT               NOT NULL,
    event_name            TEXT               NOT NULL,
    event_address         TEXT               NOT NULL,
    event_uid             TEXT               NOT NULL,
    payload               TEXT               NOT NULL
);