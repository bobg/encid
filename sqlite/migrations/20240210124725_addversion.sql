-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

CREATE TABLE IF NOT EXISTS version (
  singleton INTEGER NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  CHECK (singleton = 0)
);

INSERT OR IGNORE INTO version (singleton, version) VALUES (0, 1);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
