package service

import (
	"database/sql"
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
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
	log.Info("Connecting to postgres DB")

	// initialize connection string
	connectionString = fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s sslmode=verify-full",
		conf.UserDB.Host, conf.UserDB.User, conf.UserDB.Password, conf.UserDB.Name)

	// intialize connection object
	var err error
	postgresDB, err = sql.Open(dbDriverName, connectionString)
	if err != nil {
		log.Fatal("Failed to intialize connection object:", err.Error())
	}

	// verify connection is alive, establishing connection if necessary
	err = postgresDB.Ping()
	if err != nil {
		log.Fatal("Ping failed, cannot establish connection:", err.Error())
	}

	// Handle Terminate Signal(Ctrl + C) gracefully
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info("Disconnecting postgres DB")
		if postgresDB != nil {
			_ = postgresDB.Close()
		}
		log.Fatal("hwsc-user-svc terminated")
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

	const userSchema = `
DROP SCHEMA IF EXISTS user_svc CASCADE;

CREATE SCHEMA user_svc;

CREATE DOMAIN user_svc.user_name AS
  VARCHAR(32) NOT NULL CHECK (VALUE ~ '^[[:alpha:]]+(([''.\s-][[:alpha:]\s])?[[:alpha:]]*)*$');

CREATE DOMAIN user_svc.ulid AS
  VARCHAR(26) NOT NULL CHECK (LENGTH(VALUE) = 26);

CREATE DOMAIN user_svc.ksuid AS
  VARCHAR(27) NOT NULL CHECK (LENGTH(VALUE) = 27);

CREATE TABLE user_svc.accounts
(
  uuid              user_svc.ulid PRIMARY KEY,
  first_name        user_svc.user_name,
  last_name         user_svc.user_name,
  email             VARCHAR(320) NOT NULL UNIQUE,
  prospective_email	VARCHAR(320) UNIQUE DEFAULT NULL,
  password          VARCHAR(60) NOT NULL,
  organization      TEXT,
  created_date      TIMESTAMPTZ NOT NULL,
  modified_date		TIMESTAMPTZ DEFAULT NULL,
  is_verified       BOOLEAN NOT NULL
);

CREATE TABLE user_svc.pending_tokens
(
  token         TEXT PRIMARY KEY,
  created_date  TIMESTAMP NOT NULL,
  uuid          user_svc.ulid REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE
);

CREATE TABLE user_svc.documents
(
  uuid      user_svc.ulid REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE,
  duid      user_svc.ksuid PRIMARY KEY,
  is_public BOOLEAN NOT NULL
);

CREATE TABLE user_svc.shared_documents
(
  PRIMARY KEY (uuid, duid),
  uuid user_svc.ulid   REFERENCES user_svc.accounts(uuid) ON DELETE CASCADE,
  duid user_svc.ksuid  REFERENCES user_svc.documents(duid) ON DELETE CASCADE
);

INSERT INTO user_svc.accounts (uuid, first_name, last_name, email, password, organization, created_date, is_verified)
VALUES
    ('1000xsnjg0mqjhbf4qx1efd6y7', 'Test Delete', 'Delete', 'delete@test.com', '12345678', 'delete', current_timestamp, TRUE),
	('0000xsnjg0mqjhbf4qx1efd6y5', 'Mary-Jo', 'Allen', 'mary@test.com', '12345678', 'abc', current_timestamp, TRUE),
	('0000xsnjg0mqjhbf4qx1efd6y6', 'John F', 'Kennedy', 'john@test.com', '12345678', '123', current_timestamp, TRUE),
    ('0000xsnjg0mqjhbf4qx1efd6y3', 'Lisa', 'Kim', 'lisa@test.com', '12345678', 'uwb', current_timestamp, TRUE),
    ('0000xsnjg0mqjhbf4qx1efd6y4', 'Kate Swan', 'Smith-Jones', 'kate@test.com', '12345678', 'cse', current_timestamp, TRUE);
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
		log.Error("Failed to ping and reconnect to postgres db:", err.Error())
		return err
	}

	return nil
}

// insertNewUser inserts new users to user_svc.accounts table
// Returns error if User is nil or if error with inserting to database
func insertNewUser(user *pb.User) error {
	if user == nil {
		return errNilRequestUser
	}

	command := `
				INSERT INTO user_svc.accounts(
					uuid, first_name, last_name, email, password, organization, created_date, is_verified
				) VALUES($1, $2, $3, $4, $5, $6, $7, $8)
				`

	_, err := postgresDB.Exec(command, user.GetUuid(), user.GetFirstName(), user.GetLastName(),
		user.GetEmail(), user.GetPassword(), user.GetOrganization(), time.Now().UTC(), user.GetIsVerified())

	if err != nil {
		return err
	}

	return nil
}

// insertToken inserts to user_svc.pending_tokens
// Returns error if strings are empty or error with inserting to database
func insertToken(uuid string, token string) error {
	if uuid == "" {
		return errInvalidUUID
	}

	if token == "" {
		return errInvalidToken
	}

	command := `INSERT INTO user_svc.pending_tokens(token, created_date, uuid) VALUES($1, $2, $3)`
	_, err := postgresDB.Exec(command, token, time.Now().UTC(), uuid)

	if err != nil {
		return err
	}

	return nil
}

// checkUserExists looks up a uuid in accounts table
// Returns true if it exists, false if nonexistent
func checkUserExists(uuid string) (bool, error) {
	if uuid == "" {
		return false, errInvalidUUID
	}

	command := `SELECT uuid FROM user_svc.accounts WHERE uuid = $1`
	row, err := postgresDB.Query(command, uuid)

	if err != nil {
		return false, err
	}

	for row.Next() {
		var uid string
		if err := row.Scan(&uid); err != nil {
			return false, err
		}

		if uuid == uid {
			return true, nil
		}
	}

	return false, nil
}

// deleteUser deletes user from user_svc.accounts
// Returns error if string is empty or error with deleting from database
func deleteUser(uuid string) error {
	if uuid == "" {
		return errInvalidUUID
	}

	command := `DELETE FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1`
	_, err := postgresDB.Exec(command, uuid)

	if err != nil {
		return err
	}

	return nil
}

// getUserRow looks up a user by its uuid and stores the result in a pb.User struct
// Returns pb.User struct if found, nil otherwise
func getUserRow(uuid string) (*pb.User, error) {
	if uuid == "" {
		return nil, errInvalidUUID
	}

	command := `SELECT uuid, first_name, last_name, email, organization, created_date, is_verified
				FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1
				`
	row, err := postgresDB.Query(command, uuid)
	if err != nil {
		return nil, err
	}

	for row.Next() {
		var uid, firstName, lastName, email, organization string
		var isVerified bool
		var createdDate time.Time

		err := row.Scan(&uid, &firstName, &lastName, &email, &organization, &createdDate, &isVerified)
		if err != nil {
			return nil, err
		}

		if uuid == uid {
			return &pb.User{
				Uuid:         uid,
				FirstName:    firstName,
				LastName:     lastName,
				Email:        email,
				Organization: organization,
				CreatedDate:  createdDate.Unix(),
				IsVerified: isVerified,
			}, nil
		}
	}

	return nil, nil
}

// updateUser does a partial update by going through each User fields and replacing values
// that are different from original values. It's partial b/c some fields like created_date & uuid are not touched
// Return error if params are zero values or querying problem
func updateUserRow(uuid string, svcDerived *pb.User, dbDerived *pb.User) error {
	if uuid == "" {
		return errInvalidUUID
	}

	if svcDerived == nil || dbDerived == nil {
		return errNilRequestUser
	}

	newFirstName := dbDerived.GetFirstName()
	if svcDerived.GetFirstName() != "" && svcDerived.GetFirstName() != newFirstName {
		if err := validateFirstName(svcDerived.GetFirstName()); err != nil {
			return err
		}
		newFirstName = svcDerived.GetFirstName()
	}

	newLastName := dbDerived.GetLastName()
	if svcDerived.GetLastName() != "" && svcDerived.GetLastName() != newLastName {
		if err := validateLastName(svcDerived.GetLastName()); err != nil {
			return err
		}
		newLastName = svcDerived.GetLastName()
	}

	newOrganization := dbDerived.GetOrganization()
	if svcDerived.GetOrganization() != "" && svcDerived.GetOrganization() != newOrganization {
		if err := validateOrganization(svcDerived.GetOrganization()); err != nil {
			return err
		}
		newOrganization = svcDerived.GetOrganization()
	}

	newEmail := ""
	var newEmailToken string
	if svcDerived.GetEmail() != "" && svcDerived.GetEmail() != dbDerived.GetEmail() {
		if err := validateEmail(svcDerived.GetEmail()); err != nil {
			return err
		}
		newEmail = svcDerived.GetEmail()

		// create unique email token
		token, err := generateEmailToken()
		if err != nil {
			return err
		}
		newEmailToken = token
	}

	newHashedPassword := dbDerived.GetPassword()
	if svcDerived.GetPassword() != "" {
		// hash password using bcrypt
		hashedPassword, err := hashPassword(svcDerived.GetPassword())
		if err != nil {
			return err
		}
		newHashedPassword = hashedPassword
	}

	if (newFirstName == "" && newLastName == "" && newOrganization == "" && newHashedPassword == "" && newEmail == "") {
		return errEmptyRequestUser
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
		return err
	}

	if newEmailToken != "" {
		// insert token into db
		if err := insertToken(uuid, newEmailToken); err != nil {
			if err := deleteUser(uuid); err != nil {
				return err
			}
			return err
		}
	}

	return nil
}
