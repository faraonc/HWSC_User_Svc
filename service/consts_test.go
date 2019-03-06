package service

import (
	"fmt"
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	pblib "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	"golang.org/x/net/context"
	"time"
)

var (
	unitTestFailValue    = "shouldFail"
	unitTestFailEmail    = "should@fail.com"
	unitTestEmailCounter = 1
	unitTestDefaultUser  = &pblib.User{
		FirstName:    "Unit Test",
		Organization: "Unit Testing",
	}

	validTokenHeader = &auth.Header{
		Alg:      auth.Hs256,
		TokenTyp: auth.Jwt,
	}

	validTokenBody = &auth.Body{
		Permission:          auth.User,
		ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(authTokenExpirationTime)).Unix(),
	}
)

func unitTestEmailGenerator() string {
	email := "hwsc.test+user" + fmt.Sprint(unitTestEmailCounter) + "@gmail.com"
	unitTestEmailCounter++

	return email
}

func unitTestUserGenerator(lastName string) *pblib.User {
	return &pblib.User{
		FirstName:    unitTestDefaultUser.GetFirstName(),
		LastName:     lastName,
		Email:        unitTestEmailGenerator(),
		Password:     lastName,
		Organization: unitTestDefaultUser.Organization,
	}
}

func unitTestInsertUser(lastName string) (*pbsvc.UserResponse, error) {
	insertUser := unitTestUserGenerator(lastName)
	s := Service{}

	return s.CreateUser(context.TODO(), &pbsvc.UserRequest{User: insertUser})
}

func unitTestDeleteSecretTable() error {
	_, err := postgresDB.Exec("DELETE FROM user_security.secrets")
	if err != nil {
		return err
	}

	// active_secret is set to ON CASCADE DELETE, if foregin key (secret_key)
	// it references from secrets table is deleted, but just in case
	_, err = postgresDB.Exec("DELETE FROM user_security.active_secret")

	currSecret = nil
	return err
}

func unitTestDeleteInsertGetSecret() (*pblib.Secret, error) {
	if err := unitTestDeleteSecretTable(); err != nil {
		return nil, err
	}

	if err := insertNewSecret(); err != nil {
		return nil, err
	}

	return getActiveSecretRow()
}

func unitTestInsertNewToken() (*pblib.Secret, string, error) {
	// delete tokens table
	_, err := postgresDB.Exec("DELETE FROM user_security.auth_tokens")
	if err != nil {
		return nil, "", err
	}

	// delete secrets table and generate a new secret
	newSecret, err := unitTestDeleteInsertGetSecret()
	if err != nil {
		return nil, "", err
	}
	time.Sleep(2 * time.Second)

	validUUID, err := generateUUID()
	if err != nil {
		return nil, "", err
	}
	validTokenBody.UUID = validUUID

	// generate new token
	newToken, err := auth.NewToken(validTokenHeader, validTokenBody, newSecret)
	if err != nil {
		return nil, "", err
	}

	// insert a token
	if err := insertAuthToken(newToken, validTokenHeader, validTokenBody, newSecret); err != nil {
		return nil, "", err
	}

	return newSecret, newToken, nil
}
