-- +goose Up
ALTER TABLE keys RENAME TO encid_keys;

ALTER INDEX keys_typ_index RENAME TO encid_keys_typ_index;

ALTER TABLE version RENAME TO encid_version;

-- +goose Down
ALTER TABLE encid_keys RENAME TO keys;

ALTER INDEX encid_keys_typ_index RENAME TO keys_typ_index;

ALTER TABLE encid_version RENAME TO version;
