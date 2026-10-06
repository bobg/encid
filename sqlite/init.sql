CREATE TABLE IF NOT EXISTS encid_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  typ INTEGER NOT NULL,
  k BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS encid_keys_typ_index ON encid_keys (typ);

CREATE TABLE IF NOT EXISTS encid_version (
  singleton INTEGER NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  CONSTRAINT singleton_check CHECK (singleton = 0)
);

INSERT OR IGNORE INTO encid_version (singleton, version) VALUES (0, 1);
