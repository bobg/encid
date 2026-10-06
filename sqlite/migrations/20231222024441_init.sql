-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  typ INTEGER NOT NULL,
  k BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS keys_typ_index ON keys (typ);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS keys_typ_index;

DROP TABLE IF EXISTS keys;
-- +goose StatementEnd
