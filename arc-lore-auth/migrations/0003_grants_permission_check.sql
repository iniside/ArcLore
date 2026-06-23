-- +goose NO TRANSACTION
-- +goose Up
-- +goose StatementBegin
PRAGMA foreign_keys=OFF;
-- +goose StatementEnd
-- +goose StatementBegin
BEGIN;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE grants_new (                    -- per-user per-resource permissions
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  resource_id  TEXT NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
  permission   TEXT NOT NULL,               -- read|write|owner|admin|obliterate|migrate
  PRIMARY KEY (username, resource_id, permission),
  CHECK (permission IN ('read','write','owner','admin','obliterate','migrate'))
);
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO grants_new SELECT * FROM grants;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE grants;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE grants_new RENAME TO grants;
-- +goose StatementEnd
-- +goose StatementBegin
COMMIT;
-- +goose StatementEnd
-- +goose StatementBegin
PRAGMA foreign_key_check;
-- +goose StatementEnd
-- +goose StatementBegin
PRAGMA foreign_keys=ON;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
PRAGMA foreign_keys=OFF;
-- +goose StatementEnd
-- +goose StatementBegin
BEGIN;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TABLE grants_new (                    -- per-user per-resource permissions
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  resource_id  TEXT NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
  permission   TEXT NOT NULL,               -- read|write|owner|admin|obliterate|migrate
  PRIMARY KEY (username, resource_id, permission)
);
-- +goose StatementEnd
-- +goose StatementBegin
INSERT INTO grants_new SELECT * FROM grants;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE grants;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE grants_new RENAME TO grants;
-- +goose StatementEnd
-- +goose StatementBegin
COMMIT;
-- +goose StatementEnd
-- +goose StatementBegin
PRAGMA foreign_key_check;
-- +goose StatementEnd
-- +goose StatementBegin
PRAGMA foreign_keys=ON;
-- +goose StatementEnd
