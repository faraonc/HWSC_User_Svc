CREATE TYPE permission_level AS ENUM
(
  'NO_PERM',
  'USER_REGISTRATION',
  'USER',
  'ADMIN'
);

-- https://github.com/oklog/ulid
CREATE DOMAIN ulid AS
  VARCHAR(26) NOT NULL CHECK (LENGTH(VALUE) = 26);




CREATE SCHEMA user_svc;

CREATE DOMAIN user_svc.user_name AS
  VARCHAR(32) NOT NULL CHECK (VALUE ~ '^[[:alpha:]]+(([''.\s-][[:alpha:]\s])?[[:alpha:]]*)*$');

-- https://github.com/segmentio/ksuid
CREATE DOMAIN user_svc.ksuid AS
  VARCHAR(27) NOT NULL CHECK (LENGTH(VALUE) = 27);

CREATE TABLE user_svc.accounts
(
  uuid              ulid PRIMARY KEY,
  first_name        user_svc.user_name,
  last_name         user_svc.user_name,
  email             VARCHAR(320) NOT NULL UNIQUE,
  prospective_email	VARCHAR(320) UNIQUE DEFAULT NULL,
  password          VARCHAR(60) NOT NULL,
  organization      TEXT,
  created_date      TIMESTAMPTZ NOT NULL,
  modified_date     TIMESTAMPTZ DEFAULT NULL,
  is_verified       BOOLEAN NOT NULL,
  permission_level  permission_level NOT NULL
);

CREATE TABLE user_svc.pending_tokens
(
  token             TEXT PRIMARY KEY,
  created_date      TIMESTAMPTZ NOT NULL,
  uuid              ulid UNIQUE REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE
);

CREATE TABLE user_svc.documents
(
  duid      user_svc.ksuid PRIMARY KEY,
  uuid      ulid REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE,
  is_public BOOLEAN NOT NULL
);

-- uuid and duid act as unique identifier b/c docs can be shared to any user
CREATE TABLE user_svc.shared_documents
(
  PRIMARY KEY (duid, uuid),
  duid user_svc.ksuid  REFERENCES user_svc.documents(duid) ON DELETE CASCADE,
  uuid ulid   REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE
);





CREATE SCHEMA user_security;

CREATE TYPE user_security.algorithm_type AS ENUM
(
  'NO_ALG',
  'HS256',
  'HS512'
);

CREATE TYPE user_security.token_type AS ENUM
(
  'NO_TYPE',
  'JWT'
);

CREATE TABLE user_security.secrets
(
  secret_key            TEXT PRIMARY KEY,
  created_timestamp     TIMESTAMPTZ NOT NULL,
  expiration_timestamp  TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_security.tokens
(
  token_string      TEXT PRIMARY KEY,
  secret_key        TEXT REFERENCES user_security.secrets(secret_key) ON DELETE CASCADE,
  token_type        user_security.token_type NOT NULL,
  algorithm         user_security.algorithm_type NOT NULL,
  permission        permission_level NOT NULL,
  expiration_date   TIMESTAMPTZ NOT NULL,
  uuid              ulid NOT NULL
);
