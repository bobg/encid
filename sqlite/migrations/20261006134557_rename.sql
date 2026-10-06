-- +goose Up
ALTER TABLE keys RENAME TO encid_keys;

DROP INDEX keys_typ_index;
CREATE INDEX encid_keys_typ_index ON encid_keys (typ);

ALTER TABLE version RENAME TO encid_version;

-- +goose Down
ALTER TABLE encid_keys RENAME TO keys;

DROP INDEX encid_keys_typ_index;
CREATE INDEX keys_typ_index ON keys (typ);

ALTER TABLE encid_version RENAME TO version;
