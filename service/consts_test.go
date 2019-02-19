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
		ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(jwtExpirationTime)).Unix(),
	}
)

func init() {
	templateDirectory = "../tmpl/"
}

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

// TODO temporary, remove after removing pending token is implemented
func unitTestRemovePendingToken(uuid string) error {
	command := `DELETE FROM user_svc.pending_tokens WHERE uuid = $1`
	_, err := postgresDB.Exec(command, uuid)
	return err
}

func deleteSecretTable() error {
	_, err := postgresDB.Exec("DELETE FROM user_security.secret")
	return err
}

func deleteInsertGetSecret() (*pblib.Secret, error) {
	if err := deleteSecretTable(); err != nil {
		return nil, err
	}

	if err := insertNewSecret(); err != nil {
		return nil, err
	}

	return getActiveSecretRow()
}
