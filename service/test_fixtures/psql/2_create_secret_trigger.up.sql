CREATE TABLE user_security.active_secret
(
  secret_key            TEXT REFERENCES user_security.secrets(secret_key) ON DELETE CASCADE,
  created_timestamp     TIMESTAMPTZ,
  expiration_timestamp  TIMESTAMPTZ,
  one_row               bool PRIMARY KEY DEFAULT TRUE CONSTRAINT one_row_allowed CHECK(one_row)
);

CREATE FUNCTION insert_new_active_secret() RETURNS trigger AS
$BODY$
BEGIN
  EXECUTE 'DELETE FROM user_security.active_secret';
  INSERT INTO user_security.active_secret(secret_key, created_timestamp, expiration_timestamp, one_row)
  VALUES(NEW.secret_key, NEW.created_timestamp, NEW.expiration_timestamp, TRUE);
  RETURN NEW;
END;
$BODY$
LANGUAGE plpgsql;

CREATE TRIGGER update_active_secret
  AFTER INSERT ON user_security.secrets
  FOR EACH ROW
EXECUTE PROCEDURE insert_new_active_secret();
