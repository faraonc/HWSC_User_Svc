package service

import (
	"database/sql"
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
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

type tokenAuthRow struct {
	uuid       string
	permission string
	token      string
	secret     *pblib.Secret
}

type tokenEmailRow struct {
	token               string
	createdTimestamp    int64
	expirationTimestamp int64
	uuid                string
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
				    organization, created_timestamp, is_verified, permission_level
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

// insertEmailToken inserts received token to user_svc.email_tokens.
// Returns error if strings are empty or error with inserting to database.
func insertEmailToken(uuid string, token string) error {
	// check if uuid is valid form
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return err
	}

	if token == "" {
		return authconst.ErrEmptyToken
	}

	createdTimestamp := time.Now().UTC()
	expirationTimestamp, err := generateExpirationTimestamp(createdTimestamp, daysInTwoWeeks)
	if err != nil {
		return err
	}

	command := `INSERT INTO user_svc.email_tokens(token, created_timestamp, expiration_timestamp, uuid) 
				VALUES($1, $2, $3, $4)
				`
	_, err = postgresDB.Exec(command, token, createdTimestamp, expirationTimestamp, uuid)

	if err != nil {
		return err
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
       				created_timestamp, is_verified, password, permission_level, prospective_email
				FROM user_svc.accounts WHERE user_svc.accounts.uuid = $1
				`
	row, err := postgresDB.Query(command, uuid)
	if err != nil {
		return nil, err
	}

	defer row.Close()

	var foundUser *pblib.User
	for row.Next() {
		var prospectiveEmailNullable sql.NullString
		var uid, firstName, lastName, email, organization, password, permissionLevel, prospectiveEmail string
		var isVerified bool
		var createdTimestamp time.Time

		err := row.Scan(&uid, &firstName, &lastName, &email, &organization,
			&createdTimestamp, &isVerified, &password, &permissionLevel, &prospectiveEmailNullable)
		if err != nil {
			return nil, err
		}

		if prospectiveEmailNullable.Valid {
			prospectiveEmail = prospectiveEmailNullable.String
		}

		foundUser = &pblib.User{
			Uuid:             uid,
			FirstName:        firstName,
			LastName:         lastName,
			Email:            email,
			Organization:     organization,
			CreatedTimestamp: createdTimestamp.Unix(),
			IsVerified:       isVerified,
			Password:         password,
			PermissionLevel:  permissionLevel,
			ProspectiveEmail: prospectiveEmail,
		}
	}
	if err := row.Err(); err != nil {
		return nil, err
	}

	if foundUser == nil {
		return nil, consts.ErrUserNotFound
	}

	return foundUser, nil
}

// updateUser does a partial update by going through each User fields and replacing values.
// that are different from original values. It's partial b/c some fields like created_timestamp & uuid are not touched.
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

	newHashedPassword := dbDerived.GetPassword()
	if svcDerived.GetPassword() != "" {
		// hash password using bcrypt
		hashedPassword, err := hashPassword(svcDerived.GetPassword())
		if err != nil {
			return nil, err
		}
		newHashedPassword = hashedPassword
	}

	newIsVerified := dbDerived.GetIsVerified()

	newEmail := ""
	var newEmailToken string
	if svcDerived.GetEmail() != "" && svcDerived.GetEmail() != dbDerived.GetEmail() {
		if err := validateEmail(svcDerived.GetEmail()); err != nil {
			return nil, err
		}
		newEmail = svcDerived.GetEmail()

		emailTaken, err := isEmailTaken(newEmail)
		if err != nil {
			return nil, err
		}

		if emailTaken {
			return nil, consts.ErrEmailExists
		}

		// create unique email token
		token, err := generateSecretKey(emailTokenByteSize)
		if err != nil {
			// does not return error because we can regen a token and thus resend email
			logger.Error(consts.UpdatingUserRowTag, consts.MsgErrGeneratingEmailToken, err.Error())
		}
		newEmailToken = token
		newIsVerified = false
	}

	if newFirstName == "" && newLastName == "" && newOrganization == "" && newHashedPassword == "" && newEmail == "" {
		return nil, consts.ErrEmptyRequestUser
	}

	command := `UPDATE user_svc.accounts SET 
                	first_name = $2,
                    last_name = $3, 
                    organization = $4, 
                    password = $5, 
                    prospective_email = (CASE WHEN LENGTH($6) = 0 THEN NULL ELSE $6 END),
					is_verified = $7,
                    modified_timestamp = $8
				WHERE user_svc.accounts.uuid = $1
				`
	_, err := postgresDB.Exec(command, uuid, newFirstName, newLastName, newOrganization,
		newHashedPassword, newEmail, newIsVerified, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	updatedUser := &pblib.User{
		Uuid:             uuid,
		FirstName:        newFirstName,
		LastName:         newLastName,
		Organization:     newOrganization,
		Email:            newEmail,
		IsVerified:       newIsVerified,
		ProspectiveEmail: newEmail,
	}

	// new email process
	if newEmailToken != "" {
		// do not return error b/c we can resend verification emails

		if err := insertEmailToken(uuid, newEmailToken); err != nil {
			logger.Error(consts.UpdateUserTag, consts.MsgErrInsertEmailToken, err.Error())
		}

		// generate a new verification link
		verificationLink, err := generateEmailVerifyLink(newEmailToken)
		if err != nil {
			logger.Error(consts.UpdateUserTag, consts.MsgErrGeneratingEmailVerifyLink, err.Error())
		}

		// send email
		emailData := make(map[string]string)
		if verificationLink != "" {
			emailData[verificationLinkKey] = verificationLink
		}

		emailReq, err := newEmailRequest(emailData, []string{newEmail}, conf.EmailHost.Username, subjectUpdateEmail)
		if err != nil {
			logger.Error(consts.UpdateUserTag, consts.MsgErrEmailRequest, err.Error())
		}
		if err := emailReq.sendEmail(templateUpdateEmail); err != nil {
			logger.Error(consts.UpdateUserTag, consts.MsgErrSendEmail, err.Error())
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
	expirationTimestamp, err := generateExpirationTimestamp(createdTimestamp, daysInOneWeek)
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

// insertAuthToken inserts new token information for auditing in the database.
// Returns error if parameters are zero values, expired secret, db error.
func insertAuthToken(token string, header *auth.Header, body *auth.Body, secret *pblib.Secret) error {
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
					token, secret_key, token_type, algorithm,
					permission, expiration_timestamp, uuid
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

// getAuthTokenRow looks up existing user and grabs row where token is not expired from the auth_tokens table.
// Once matched, inner join will join a row from secrets table that matches its secrets_key with
// the matched token's row secret_key.
// Returns tokenAuthRow object if existing token is found and unexpired, nil if not found, else errors.
func getAuthTokenRow(uuid string) (*tokenAuthRow, error) {
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, authconst.ErrInvalidUUID
	}

	command := `SELECT uuid, permission, token, user_security.auth_tokens.secret_key, 
       				user_security.secrets.created_timestamp, user_security.secrets.expiration_timestamp
				FROM user_security.auth_tokens
				INNER JOIN user_security.secrets
				ON user_security.secrets.secret_key = user_security.auth_tokens.secret_key
				WHERE uuid = $1 AND NOW() AT TIME ZONE 'UTC' < user_security.auth_tokens.expiration_timestamp
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

		return &tokenAuthRow{
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

	return nil, consts.ErrNoAuthTokenFound
}

// pairTokenWithSecret will look up matching token in the tokens table.
// Once matched, inner join will join the matching secret_key row in secrets table with matched tokens row secret_key.
// Returns secret object for the found token.
func pairTokenWithSecret(token string) (*pblib.Identification, error) {
	if token == "" {
		return nil, authconst.ErrEmptyToken
	}

	command := `SELECT token, user_security.auth_tokens.secret_key, 
					user_security.secrets.created_timestamp, user_security.secrets.expiration_timestamp
				FROM user_security.auth_tokens
				INNER JOIN user_security.secrets
				ON user_security.auth_tokens.secret_key = user_security.secrets.secret_key
				WHERE token = $1
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

	return nil, consts.ErrNoMatchingAuthTokenFound
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

// isEmailTaken takes received email and checks it against user_svc.accounts table for
// existing email in both email and prospective_email columns.
// On success querying, returns true if exists, false otherwise.
func isEmailTaken(prospectiveEmail string) (bool, error) {
	if err := validateEmail(prospectiveEmail); err != nil {
		return false, err
	}

	// do a query to check prospective_email is not a existing email for someone else
	command := `SELECT EXISTS(
  					SELECT email
  					FROM user_svc.accounts
  					WHERE email = $1 OR prospective_email = $1
				)`

	var emailExists bool
	err := postgresDB.QueryRow(command, prospectiveEmail).Scan(&emailExists)
	if err != nil {
		return false, err
	}

	if emailExists {
		return true, nil
	}

	return false, nil
}

// getEmailTokenRow looks up existing token from user_svc.email_tokens table.
// If token exists, the rows information are returned in a tokenEmailRow struct.
// If token does not exist, return error.
func getEmailTokenRow(token string) (*tokenEmailRow, error) {
	if token == "" {
		return nil, authconst.ErrEmptyToken
	}

	command := `SELECT * FROM user_svc.email_tokens
				WHERE token = $1`

	row, err := postgresDB.Query(command, token)
	if err != nil {
		return nil, err
	}

	defer row.Close()
	for row.Next() {
		var emailToken, uuid string
		var createdTimestamp, expirationTimestamp time.Time

		err := row.Scan(&emailToken, &createdTimestamp, &expirationTimestamp, &uuid)
		if err != nil {
			return nil, err
		}

		if token != emailToken {
			return nil, consts.ErrMismatchingEmailToken
		}

		return &tokenEmailRow{
			token:               emailToken,
			createdTimestamp:    createdTimestamp.Unix(),
			expirationTimestamp: expirationTimestamp.Unix(),
			uuid:                uuid,
		}, nil
	}

	return nil, consts.ErrNoMatchingEmailTokenFound
}

// deleteEmailTokenRow looks up the given uuid in user_svc.email_tokens table and deletes the matching row.
// Returns error if given uuid is invalid or any db error.
func deleteEmailTokenRow(uuid string) error {
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return authconst.ErrInvalidUUID
	}

	command := `DELETE FROM user_svc.email_tokens WHERE uuid = $1`

	_, err := postgresDB.Exec(command, uuid)

	if err != nil {
		return err
	}

	return nil
}

// matchEmailAndPassword looks up a row that matches the email. Then after the matched row is retrieved,
// password retrieved from db is matched with given password.
// If both email and password matches, returns the matched users row.
// If the query by email returns nothing, returns email does not exist error.
// If email is found, but password does not match, returns password does not match error.
// All other errors are returned.
func matchEmailAndPassword(email string, password string) (*pblib.User, error) {
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	command := `SELECT uuid, first_name, last_name, email, organization, 
       				created_timestamp, is_verified, password, permission_level, prospective_email
				FROM user_svc.accounts 
				WHERE email = $1
				`

	row, err := postgresDB.Query(command, email)
	if err != nil {
		return nil, err
	}

	defer row.Close()
	var foundUser *pblib.User
	for row.Next() {
		var prospectiveEmailNullable sql.NullString
		var uuid, firstName, lastName, email, organization, hashedPassword, permissionLevel, prospectiveEmail string
		var isVerified bool
		var createdTimestamp time.Time

		err := row.Scan(&uuid, &firstName, &lastName, &email, &organization,
			&createdTimestamp, &isVerified, &hashedPassword, &permissionLevel, &prospectiveEmailNullable)
		if err != nil {
			return nil, err
		}

		if prospectiveEmailNullable.Valid {
			prospectiveEmail = prospectiveEmailNullable.String
		}

		foundUser = &pblib.User{
			Uuid:             uuid,
			FirstName:        firstName,
			LastName:         lastName,
			Email:            email,
			Organization:     organization,
			CreatedTimestamp: createdTimestamp.Unix(),
			IsVerified:       isVerified,
			Password:         hashedPassword,
			PermissionLevel:  permissionLevel,
			ProspectiveEmail: prospectiveEmail,
		}
	}
	if err := row.Err(); err != nil {
		return nil, err
	}

	if foundUser == nil {
		return nil, consts.ErrEmailDoesNotExist
	}

	// match password
	if err := comparePassword(foundUser.GetPassword(), password); err != nil {
		return nil, err
	}

	return foundUser, nil
}
