CREATE UNIQUE INDEX user_svc_accounts_email_index ON user_svc.accounts(email);
CREATE INDEX user_security_secret_active_index ON user_security.secret(is_active);
