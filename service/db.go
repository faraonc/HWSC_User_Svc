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

type tokenRow struct {
	uuid       string
	permission string
	token      string
	secret     *pblib.Secret
}

const (
	dbDriverName = "postgres"
)

var (
	connectionString string
	postgresDB       *sql.DB
	currSecret       *pblib.Secret
)

func init() {
	connectionString = fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s sslmode=%s port=%s",
		conf.UserDB.Host, conf.UserDB.User, conf.UserDB.Password, conf.UserDB.Name, conf.UserDB.SSLMode, conf.UserDB.Port)

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
}

// refreshDBConnection verifies if connection is alive, ping will establish c/n if necessary.
// Returns response object if ping failed to reconnect.
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

// insertNewUser checks user field validity, hashes password and.
// Inserts new users to user_svc.accounts table.
// Returns error if User is nil or if error with inserting to database.
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

// insertToken creates a unique token and inserts to user_svc.email_tokens.
// Returns error if strings are empty or error with inserting to database.
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

	command := `INSERT INTO user_svc.email_tokens(token, created_date, uuid) VALUES($1, $2, $3)`
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

// deleteUser deletes user from user_svc.accounts.
// Deleting non-existent uuid does not throw an error, db simply returns nothing which is okay.
// Returns error if string is empty or error with deleting from database.
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

// getUserRow looks up a user by its uuid and stores the result in a pb.User struct.
// Retrieving non-existent uuid does not throw an error, db simply returns nothing.
// So we put in a check to see if uuid exists to return error if not found.
// Returns pb.User struct if found, nil otherwise, error if uuid does not exist or err with db.
func getUserRow(uuid string) (*pblib.User, error) {
	// check if uuid is valid form
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, err
	}

	command := `SELECT uuid, first_name, last_name, email, organization, 
       				created_date, is_verified, password, permission_level
				FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1
				`
	row, err := postgresDB.Query(command, uuid)
	if err != nil {
		return nil, err
	}

	defer row.Close()

	var userObject *pblib.User
	for row.Next() {
		var uid, firstName, lastName, email, organization, password, permissionLevel string
		var isVerified bool
		var createdDate time.Time

		err := row.Scan(&uid, &firstName, &lastName, &email, &organization,
			&createdDate, &isVerified, &password, &permissionLevel)
		if err != nil {
			return nil, err
		}
		userObject = &pblib.User{
			Uuid:            uid,
			FirstName:       firstName,
			LastName:        lastName,
			Email:           email,
			Organization:    organization,
			CreatedDate:     createdDate.Unix(),
			IsVerified:      isVerified,
			Password:        password,
			PermissionLevel: permissionLevel,
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

// updateUser does a partial update by going through each User fields and replacing values.
// that are different from original values. It's partial b/c some fields like created_date & uuid are not touched.
// Return error if params are zero values or querying problem.
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

// getActiveSecretRow retrieves active key information from active_secret table (constraint to one row).
// Returns secret object if a row exists, else returns nil for all other cases (secret not found).
func getActiveSecretRow() (*pblib.Secret, error) {
	command := `SELECT secret_key, created_timestamp, expiration_timestamp 
				FROM user_security.active_secret
				`

	row, err := postgresDB.Query(command)
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

	return nil, consts.ErrNoActiveSecretKeyFound
}

// insertNewSecret inserts a newly generated secret key to database.
// Secret key is used to sign JWT's.
// There is a trigger set up with secrets table in that with every insert,
// the active_secret table is updated with the newly inserted secret.
// Returns err if secret is empty or error with database.
func insertNewSecret() error {
	// generate a new secret
	secretKey, err := generateSecretKey(auth.SecretByteSize)
	if err != nil {
		return err
	}

	command := `INSERT INTO user_security.secrets(
					secret_key, created_timestamp, expiration_timestamp
				) VALUES($1, $2, $3)
				`

	createdTimestamp := time.Now().UTC()
	expirationTimestamp, err := generateSecretExpirationTimestamp(createdTimestamp)
	if err != nil {
		return err
	}

	_, err = postgresDB.Exec(command, secretKey, createdTimestamp, expirationTimestamp)

	if err != nil {
		return err
	}

	return nil
}

// getLatestSecret looks at the secrets table and selects row that is less than parameter seconds.
// Used to validate that the latest secret has been inserted into database.
// Returns the secret key string if row passes timestamp test, else empty value.
func getLatestSecret(seconds int) (string, error) {
	if seconds == 0 {
		return "", consts.ErrInvalidAddTime
	}

	interval := time.Now().UTC().Add(time.Second * time.Duration(-seconds))

	command := `
				SELECT secret_key 
				FROM user_security.secrets
				WHERE created_timestamp > $1
				`

	var secretKey string
	err := postgresDB.QueryRow(command, interval).Scan(&secretKey)
	if err != nil {
		return "", err
	}

	if secretKey == "" {
		return "", consts.ErrNoRowsFound
	}

	return secretKey, nil
}

// insertJWToken inserts new token information for auditing in the database.
// Returns error if parameters are zero values, expired secret, db error.
func insertJWToken(token string, header *auth.Header, body *auth.Body, secret *pblib.Secret) error {
	if token == "" {
		return authconst.ErrEmptyToken
	}
	if err := auth.ValidateHeader(header); err != nil {
		return err
	}
	if err := auth.ValidateBody(body); err != nil {
		return err
	}
	if err := auth.ValidateSecret(secret); err != nil {
		return err
	}

	command := `
				INSERT INTO user_security.auth_tokens(
					token_string, secret_key, token_type, algorithm,
					permission, expiration_date, uuid
				) VALUES($1, $2, $3, $4, $5, $6, $7)
				`

	_, err := postgresDB.Exec(command, token, secret.Key, auth.TokenTypeStringMap[header.TokenTyp],
		auth.AlgorithmStringMap[header.Alg], auth.PermissionStringMap[body.Permission],
		time.Unix(body.ExpirationTimestamp, 0), body.UUID)

	if err != nil {
		return err
	}

	return nil
}

// getExistingToken looks up existing user and grabs row where token is not expired from the tokens table.
// Once matched, inner join will join a row from secrets table that matches its secrets_key with
// the matched token's row secret_key.
// Returns tokenRow object if existing token is found and unexpired, nil if not found, else errors.
func getExistingToken(uuid string) (*tokenRow, error) {
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, authconst.ErrInvalidUUID
	}

	command := `SELECT uuid, permission, token_string, user_security.auth_tokens.secret_key, 
       				user_security.secrets.created_timestamp, user_security.secrets.expiration_timestamp
				FROM user_security.auth_tokens
				INNER JOIN user_security.secrets
				ON user_security.secrets.secret_key = user_security.auth_tokens.secret_key
				WHERE uuid = $1 AND NOW() AT TIME ZONE 'UTC' < expiration_date
				`

	row, err := postgresDB.Query(command, uuid)
	if err != nil {
		return nil, err
	}

	defer row.Close()
	for row.Next() {
		var retrievedUUID, permission, token, secret string
		var secretCreatedTimestamp, secretExpirationTimestamp time.Time

		err := row.Scan(&retrievedUUID, &permission, &token, &secret,
			&secretCreatedTimestamp, &secretExpirationTimestamp)
		if err != nil {
			return nil, err
		}

		if uuid != retrievedUUID {
			return nil, authconst.ErrInvalidUUID
		}

		return &tokenRow{
			uuid:       retrievedUUID,
			permission: permission,
			token:      token,
			secret: &pblib.Secret{
				Key:                 secret,
				CreatedTimestamp:    secretCreatedTimestamp.Unix(),
				ExpirationTimestamp: secretExpirationTimestamp.Unix(),
			},
		}, nil
	}

	return nil, consts.ErrNoExistingTokenFound
}

// pairTokenWithSecret will look up matching token in the tokens table.
// Once matched, inner join will join the matching secret_key row in secrets table with matched tokens row secret_key.
// Returns secret object for the found token.
func pairTokenWithSecret(token string) (*pblib.Identification, error) {
	if token == "" {
		return nil, authconst.ErrEmptyToken
	}

	command := `SELECT token_string, user_security.auth_tokens.secret_key, 
					user_security.secrets.created_timestamp, user_security.secrets.expiration_timestamp
				FROM user_security.auth_tokens
				INNER JOIN user_security.secrets
				ON user_security.auth_tokens.secret_key = user_security.secrets.secret_key
				WHERE token_string = $1
				`
	row, err := postgresDB.Query(command, token)
	if err != nil {
		return nil, err
	}

	defer row.Close()
	for row.Next() {
		var retrievedToken, secretKey string
		var secretCreatedTimeStamp, secretExpirationTimestamp time.Time

		err := row.Scan(&retrievedToken, &secretKey, &secretCreatedTimeStamp, &secretExpirationTimestamp)
		if err != nil {
			return nil, err
		}

		if token != retrievedToken {
			return nil, consts.ErrMismatchingToken
		}

		return &pblib.Identification{
			Token: retrievedToken,
			Secret: &pblib.Secret{
				Key:                 secretKey,
				CreatedTimestamp:    secretCreatedTimeStamp.Unix(),
				ExpirationTimestamp: secretExpirationTimestamp.Unix(),
			},
		}, nil
	}

	return nil, consts.ErrNoExistingTokenFound
}

// hasActiveSecret checks active_secret table for a row.
// active_secret table has a constraint to only one row.
// Returns true if a row was found, false otherwise, or any error encountered with the db itself.
func hasActiveSecret() (bool, error) {
	command := `SELECT EXISTS( 
  					SELECT *
  					FROM user_security.active_secret
  				)`

	var exists bool
	err := postgresDB.QueryRow(command).Scan(&exists)
	if err != nil {
		return false, err
	}

	if exists {
		return true, nil
	}

	return false, nil
}
