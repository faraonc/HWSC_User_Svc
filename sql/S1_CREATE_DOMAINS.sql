CREATE DOMAIN user_name AS
  VARCHAR(32) NOT NULL CHECK (VALUE ~ '^[[:alpha:]]+(([''.\s-][[:alpha:]\s])?[[:alpha:]]*)*$');

-- https://github.com/oklog/ulid
CREATE DOMAIN ulid AS
  VARCHAR(26) NOT NULL CHECK (LENGTH(VALUE) = 26);

-- https://github.com/segmentio/ksuid
CREATE DOMAIN ksuid AS
  VARCHAR(27) NOT NULL CHECK (LENGTH(VALUE) = 27);