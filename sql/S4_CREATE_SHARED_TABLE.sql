-- uuid and duid act as unique identifier b/c docs can be shared to any user
CREATE TABLE shared_documents
(
  PRIMARY KEY (uuid, duid),
  uuid ULID   REFERENCES user_account(uuid) ON DELETE CASCADE,
  duid KSUID  REFERENCES documents(duid) ON DELETE CASCADE
);