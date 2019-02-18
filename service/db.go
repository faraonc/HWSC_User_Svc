package service

import (
	"database/sql"
	"errors"
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-lib/validation"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"log"
	"time"

	// database/sql uses this library indirectly
	_ "github.com/lib/pq"
	"os"
	"os/signal"
	"syscall"
)

const (
	dbDriverName = "postgres"
)

var (
	connectionString string
	postgresDB       *sql.DB
)

func init() {
	logger.Info(consts.PSQL, "Connecting to postgres DB")

	// initialize connection string
	connectionString = fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s sslmode=verify-full",
		conf.UserDB.Host, conf.UserDB.User, conf.UserDB.Password, conf.UserDB.Name)

	// intialize connection object
	var err error
	postgresDB, err = sql.Open(dbDriverName, connectionString)
	if err != nil {
		logger.Fatal(consts.PSQL, "Failed to intialize connection object:", err.Error())
	}

	// verify connection is alive, establishing connection if necessary
	err = postgresDB.Ping()
	if err != nil {
		logger.Fatal(consts.PSQL, "Ping failed, cannot establish connection:", err.Error())
	}

	// Handle Terminate Signal(Ctrl + C) gracefully
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Info(consts.PSQL, "Disconnecting postgres DB")
		if postgresDB != nil {
			_ = postgresDB.Close()
		}
		log.Fatal(consts.PSQL, "hwsc-user-svc terminated")
	}()

	// TODO delete after dev-ops working
	devCreateUserTable()
}

// TODO delete after dev-ops working
func devCheckError(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

// TODO delete after dev-ops working
func devCreateUserTable() {
	if postgresDB == nil {
		log.Fatal("postgres connection is null for some reason")
	}

	//hashed password for integrate@update.com = testingPassword

	const userSchema = `
DROP SCHEMA IF EXISTS user_svc CASCADE;
DROP SCHEMA IF EXISTS user_security CASCADE;
DROP TYPE IF EXISTS permission_level;
DROP DOMAIN IF EXISTS ulid;

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

CREATE TABLE user_security.secret
(
  secret_key        	TEXT PRIMARY KEY,
  created_timestamp 	TIMESTAMPTZ NOT NULL,
  expiration_timestamp  TIMESTAMPTZ NOT NULL,
  is_active             BOOLEAN NOT NULL
);

CREATE TABLE user_security.tokens
(
  token_string      TEXT PRIMARY KEY,
  secret_key        TEXT REFERENCES user_security.secret(secret_key) ON DELETE CASCADE,
  token_type        user_security.token_type NOT NULL,
  algorithm         user_security.algorithm_type NOT NULL,
  permission        permission_level NOT NULL,
  expiration_date   TIMESTAMPTZ NOT NULL,
  uuid              ulid NOT NULL UNIQUE
);


INSERT INTO user_svc.accounts (uuid, first_name, last_name, email, password, organization, created_date, is_verified, permission_level)
VALUES
    ('1000xsnjg0mqjhbf4qx1efd6y7', 'Integrate Test', 'DeleteUser', 'integrate@delete.com', '12345678', 'delete', current_timestamp, TRUE, 'NO_PERM'),
	('0000xsnjg0mqjhbf4qx1efd6y5', 'Integrate Test', 'GetUser', 'integrate@get.com', '12345678', 'abc', current_timestamp, TRUE, 'NO_PERM'),
    ('0000xsnjg0mqjhbf4qx1efd6y3', 'Integrate Test', 'UpdateUser', 'integrate@update.com', '$2a$04$k0Ee2g8dwRV.xTrBBxKWQupAZUyVYAP5AiwEBQm1DP3nz9uJhs/WG', 'uwb', current_timestamp, TRUE, 'NO_PERM');

INSERT INTO user_security.secret (secret_key, created_timestamp, expiration_timestamp, is_active)
VALUES
  ('Integrate-Test-Active-Secret', current_timestamp, current_timestamp, true),
  ('Integrate-Wrong-Secret', current_timestamp, current_timestamp, false);
`
	_, err := postgresDB.Exec(userSchema)
	devCheckError(err)
}

// refreshDBConnection verifies if connection is alive, ping will establish c/n if necessary
// Returns response object if ping failed to reconnect
func refreshDBConnection() error {
	if postgresDB == nil {
		var err error
		postgresDB, err = sql.Open(dbDriverName, connectionString)
		if err != nil {
			return err
		}
	}

	if err := postgresDB.Ping(); err != nil {
		_ = postgresDB.Close()
		postgresDB = nil
		logger.Error(consts.PSQL, "Failed to ping and reconnect to postgres db:", err.Error())
		return err
	}

	return nil
}

// insertNewUser checks user field validity, hashes password and
// inserts new users to user_svc.accounts table
// Returns error if User is nil or if error with inserting to database
func insertNewUser(user *pblib.User) error {
	if user == nil {
		return consts.ErrNilRequestUser
	}

	// check if uuid is valid form
	if err := validation.ValidateUserUUID(user.GetUuid()); err != nil {
		return err
	}

	// validate fields in user object
	if err := validateUser(user); err != nil {
		return err
	}

	// hash password using bcrypt
	hashedPassword, err := hashPassword(user.GetPassword())
	if err != nil {
		return err
	}

	command := `
				INSERT INTO user_svc.accounts(
					uuid, first_name, last_name, email, password, 
				    organization, created_date, is_verified, permission_level
				) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
				`

	_, err = postgresDB.Exec(command, user.GetUuid(), user.GetFirstName(), user.GetLastName(),
		user.GetEmail(), hashedPassword, user.GetOrganization(),
		time.Now().UTC(), false, auth.PermissionStringMap[auth.User])

	if err != nil {
		return err
	}

	return nil
}

// insertToken creates a unique token and inserts to user_svc.pending_tokens
// Returns error if strings are empty or error with inserting to database
func insertEmailToken(uuid string) error {
	// check if uuid is valid form
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return err
	}

	// create unique email token
	token, err := generateSecretKey(emailTokenByteSize)
	if err != nil {
		return err
	}

	command := `INSERT INTO user_svc.pending_tokens(token, created_date, uuid) VALUES($1, $2, $3)`
	_, err = postgresDB.Exec(command, token, time.Now().UTC(), uuid)

	if err != nil {
		combinedErr := err.Error()
		if deleteErr := deleteUserRow(uuid); deleteErr != nil {
			combinedErr += deleteErr.Error()
		}
		return errors.New(combinedErr)
	}

	return nil
}

// deleteUser deletes user from user_svc.accounts
// deleting non-existent uuid does not throw an error, db simply returns nothing which is okay
// Returns error if string is empty or error with deleting from database
func deleteUserRow(uuid string) error {
	// check if uuid is valid form
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return err
	}

	command := `DELETE FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1`
	_, err := postgresDB.Exec(command, uuid)

	if err != nil {
		return err
	}

	return nil
}

// getUserRow looks up a user by its uuid and stores the result in a pb.User struct
// retrieving non-existent uuid does not throw an error, db simply returns nothing
// so we put in a check to see if uuid exists to return error if not found
// Returns pb.User struct if found, nil otherwise, error if uuid does not exist or err with db
func getUserRow(uuid string) (*pblib.User, error) {
	// check if uuid is valid form
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, err
	}

	command := `SELECT uuid, first_name, last_name, email, organization, created_date, is_verified, password
				FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1
				`
	row, err := postgresDB.Query(command, uuid)
	if err != nil {
		return nil, err
	}

	defer row.Close()

	var userObject *pblib.User
	for row.Next() {
		var uid, firstName, lastName, email, organization, password string
		var isVerified bool
		var createdDate time.Time

		err := row.Scan(&uid, &firstName, &lastName, &email, &organization, &createdDate, &isVerified, &password)
		if err != nil {
			return nil, err
		}
		userObject = &pblib.User{
			Uuid:         uid,
			FirstName:    firstName,
			LastName:     lastName,
			Email:        email,
			Organization: organization,
			CreatedDate:  createdDate.Unix(),
			IsVerified:   isVerified,
			Password:     password,
		}
	}
	if err := row.Err(); err != nil {
		return nil, err
	}

	if userObject.GetUuid() != uuid {
		return nil, authconst.ErrInvalidUUID
	}

	return userObject, nil
}

// updateUser does a partial update by going through each User fields and replacing values
// that are different from original values. It's partial b/c some fields like created_date & uuid are not touched
// Return error if params are zero values or querying problem
func updateUserRow(uuid string, svcDerived *pblib.User, dbDerived *pblib.User) (*pblib.User, error) {
	if svcDerived == nil || dbDerived == nil {
		return nil, consts.ErrNilRequestUser
	}

	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, err
	}

	newFirstName := dbDerived.GetFirstName()
	if svcDerived.GetFirstName() != "" && svcDerived.GetFirstName() != newFirstName {
		if err := validateFirstName(svcDerived.GetFirstName()); err != nil {
			return nil, err
		}
		newFirstName = svcDerived.GetFirstName()
	}

	newLastName := dbDerived.GetLastName()
	if svcDerived.GetLastName() != "" && svcDerived.GetLastName() != newLastName {
		if err := validateLastName(svcDerived.GetLastName()); err != nil {
			return nil, err
		}
		newLastName = svcDerived.GetLastName()
	}

	newOrganization := dbDerived.GetOrganization()
	if svcDerived.GetOrganization() != "" && svcDerived.GetOrganization() != newOrganization {
		if err := validateOrganization(svcDerived.GetOrganization()); err != nil {
			return nil, err
		}
		newOrganization = svcDerived.GetOrganization()
	}

	newEmail := ""
	var newEmailToken string
	if svcDerived.GetEmail() != "" && svcDerived.GetEmail() != dbDerived.GetEmail() {
		if err := validateEmail(svcDerived.GetEmail()); err != nil {
			return nil, err
		}
		newEmail = svcDerived.GetEmail()

		// create unique email token
		token, err := generateSecretKey(emailTokenByteSize)
		if err != nil {
			return nil, err
		}
		newEmailToken = token
	}

	newHashedPassword := dbDerived.GetPassword()
	if svcDerived.GetPassword() != "" {
		// hash password using bcrypt
		hashedPassword, err := hashPassword(svcDerived.GetPassword())
		if err != nil {
			return nil, err
		}
		newHashedPassword = hashedPassword
	}

	if newFirstName == "" && newLastName == "" && newOrganization == "" && newHashedPassword == "" && newEmail == "" {
		return nil, consts.ErrEmptyRequestUser
	}

	newIsVerified := dbDerived.GetIsVerified()
	if newEmailToken != "" {
		newIsVerified = false
	}

	command := `UPDATE user_svc.accounts SET 
                	first_name = $2,
                    last_name = $3, 
                    organization = $4, 
                    password = $5, 
                    prospective_email = (CASE WHEN LENGTH($6) = 0 THEN NULL ELSE $6 END),
					is_verified = $7,
                    modified_date = $8
				WHERE user_svc.accounts.uuid = $1
				`
	_, err := postgresDB.Exec(command, uuid, newFirstName, newLastName, newOrganization,
		newHashedPassword, newEmail, newIsVerified, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	updatedUser := &pblib.User{
		Uuid:         uuid,
		FirstName:    newFirstName,
		LastName:     newLastName,
		Organization: newOrganization,
		Email:        newEmail,
		IsVerified:   newIsVerified,
	}

	if newEmailToken != "" {
		// insert token into db
		if err := insertEmailToken(uuid); err != nil {
			if err := deleteUserRow(uuid); err != nil {
				return nil, err
			}
			return nil, err
		}
	}

	return updatedUser, nil
}

// getActiveSecret retrieves the secretKey from the row where is_active is marked true
// Returns secret object if found, nil if not found, else any db error
func getActiveSecretRow() (*pblib.Secret, error) {
	command := `SELECT secret_key, created_timestamp, expiration_timestamp 
				FROM user_security.secret 
				WHERE is_active = $1`

	row, err := postgresDB.Query(command, true)
	if err != nil {
		return nil, err
	}

	defer row.Close()
	var secretKey string
	var createdTimestamp, expirationTimestamp time.Time
	for row.Next() {
		err := row.Scan(&secretKey, &createdTimestamp, &expirationTimestamp)
		if err != nil {
			return nil, err
		}

		if secretKey != "" {
			return &pblib.Secret{
				Key:                 secretKey,
				CreatedTimestamp:    createdTimestamp.Unix(),
				ExpirationTimestamp: expirationTimestamp.Unix(),
			}, nil
		}
	}

	return nil, nil
}

// deactivateSecret looks up the row by secretkey and sets the row's is_active to false
// If a row wasn't match, it will still return nil safely
// Returns nil if updated or if not matched, else errors
func deactivateSecret(secretKey string) error {
	if secretKey == "" {
		return nil
	}

	command := `UPDATE user_security.secret 
				SET	is_active = $1 
				WHERE secret_key = $2
				`
	_, err := postgresDB.Exec(command, false, secretKey)
	if err != nil {
		return err
	}

	return nil
}

// insertNewSecret inserts a newly generated secret key to database
// secret key is used to sign JWT's
// Returns err if secret is empty or error with database
func insertNewSecret() error {
	// generate a new secret
	secretKey, err := generateSecretKey(auth.SecretByteSize)
	if err != nil {
		return err
	}

	command := `INSERT INTO user_security.secret(
					secret_key, created_timestamp, expiration_timestamp, is_active
				) VALUES($1, $2, $3, $4)
				`

	createdTimeStamp := time.Now().UTC()
	expirationTimestamp, err := generateSecretExpirationTimestamp(createdTimeStamp)
	if err != nil {
		return err
	}

	_, err = postgresDB.Exec(command, secretKey, createdTimeStamp, expirationTimestamp, true)

	if err != nil {
		return err
	}

	return nil
}

// queryLatestSecret looks for the secret that is less 2 minutes
// Used to validate that a new secret has been inserted into database
// Returns true if found, else false
func queryLatestSecret(minute int) (bool, error) {
	if minute == 0 {
		return false, consts.ErrInvalidAddTime
	}

	interval := time.Now().UTC().Add(time.Minute * time.Duration(-minute))

	command := `
				SELECT COUNT(*) FROM user_security.secret 
				WHERE created_timestamp > $1 AND is_active = $2
				`

	var count int
	err := postgresDB.QueryRow(command, interval, true).Scan(&count)
	if err != nil {
		return false, err
	}

	if count == 0 {
		return false, consts.ErrNoRowsFound
	}

	if count > 1 {
		return false, consts.ErrInvalidRowCount
	}

	return true, nil
}

//TODO work on later
//func insertJWToken(uuid string, header *auth.Header, body *auth.Body, token string, secretKey string) error {
//	if err := validateUUID(uuid); err != nil {
//		return consts.ErrInvalidUUID
//	}
//	if header == nil {
//		return authconst.ErrNilHeader
//	}
//	if body == nil {
//		return authconst.ErrNilBody
//	}
//	if token == "" {
//		return authconst.ErrEmptyToken
//	}
//	if secretKey == "" {
//		return authconst.ErrEmptySecret
//	}
//
//	command := `
//				INSERT INTO user_security.tokens(
//					token_string, secret_key, token_type, algorithm,
//					permission, expiration_date, uuid
//				) VALUES($1, $2, $3, $4, $5, $6, $7)
//				`
//
//	_, err := postgresDB.Exec(command, token, secretKey, header.TokenTyp, header.Alg,
//		auth.PermissionStringMap[body.Permission], time.Unix(body.ExpirationTimestamp, 0), uuid)
//
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
