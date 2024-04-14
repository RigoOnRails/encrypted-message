CREATE TABLE users (
  id CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
  json JSON NOT NULL,
  nullable_json JSON
);
