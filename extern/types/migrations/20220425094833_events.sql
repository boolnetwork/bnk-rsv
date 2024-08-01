-- Add migration script here
CREATE TABLE IF NOT EXISTS events
(
    blockNumber         INTEGER             NOT NULL,
    transactionIndex    INTEGER             NOT NULL,
    logIndex            INTEGER             NOT NULL,
    transactionHash     TEXT                NOT NULL,
    eventName           TEXT                NOT NULL,
    txFrom              TEXT                NOT NULL,
    txTo                TEXT                NOT NULL,
    txValue             TEXT                NOT NULL,
    txInput             BLOB                NOT NULL,
    rawData             BLOB                NOT NULL
);