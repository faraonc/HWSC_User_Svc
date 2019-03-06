CREATE UNIQUE INDEX user_svc_accounts_email_pw_index ON user_svc.accounts(email, password);
CREATE UNIQUE INDEX user_svc_accounts_prosp_email ON user_svc.accounts(prospective_email);
