DROP TABLE IF EXISTS user_security.active_secret;
DROP TRIGGER IF EXISTS update_active_secret ON user_security.secrets;
DROP FUNCTION IF EXISTS insert_new_active_secret();
