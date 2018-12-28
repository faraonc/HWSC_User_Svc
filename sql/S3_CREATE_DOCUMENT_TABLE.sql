CREATE TABLE documents
(
  uuid      ULID REFERENCES user_account(uuid) ON DELETE CASCADE,
  duid      KSUID PRIMARY KEY,
  is_public BOOLEAN NOT NULL DEFAULT TRUE
);