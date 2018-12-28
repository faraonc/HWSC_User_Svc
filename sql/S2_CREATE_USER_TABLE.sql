CREATE TABLE user_account
(
  uuid              ULID PRIMARY KEY,
  first_name        USER_NAME,
  last_name         USER_NAME,
  email             VARCHAR(320) NOT NULL UNIQUE,
  password          VARCHAR(20) NOT NULL
                    CONSTRAINT password_length
                    CHECK(length(password) > 7),
  organization      TEXT,
  create_timestamp  TIMESTAMP NOT NULL
);