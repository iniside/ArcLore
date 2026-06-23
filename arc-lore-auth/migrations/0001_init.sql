-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
  username     TEXT PRIMARY KEY,            -- normalized lowercase
  display_name TEXT NOT NULL DEFAULT '',
  argon2id     TEXT NOT NULL,               -- PHC string
  is_admin     INTEGER NOT NULL DEFAULT 0,
  created      INTEGER NOT NULL,
  updated      INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE resources (                    -- the repo registry
  resource_id  TEXT PRIMARY KEY,            -- "urc-{repoid-hex}"
  name         TEXT NOT NULL DEFAULT '',
  created      INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE grants (                       -- per-user per-resource permissions
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  resource_id  TEXT NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
  permission   TEXT NOT NULL,               -- read|write|owner|admin|obliterate|migrate
  PRIMARY KEY (username, resource_id, permission)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE config ( key TEXT PRIMARY KEY, value TEXT NOT NULL );  -- registration_open, etc.
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE grants;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE resources;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE config;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE users;
-- +goose StatementEnd
