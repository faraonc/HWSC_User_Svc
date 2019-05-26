package service

import (
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"testing"
	"time"
)

func TestRefreshDBConnection(t *testing.T) {
	assert.NotNil(t, postgresDB)

	//verify connection on supposedly opened connection
	err := refreshDBConnection()
	assert.Nil(t, err)
	assert.NotNil(t, postgresDB)

	// close connection
	err = postgresDB.Close()
	assert.Nil(t, err)

	// test on closed connection
	err = refreshDBConnection()
	assert.NotNil(t, err)
	assert.Nil(t, postgresDB)

	//verify initializing
	err = refreshDBConnection()
	assert.Nil(t, err)
}

func TestInsertNewUser(t *testing.T) {
	// valid user
	uuid1, _ := generateUUID()
	uuid2, _ := generateUUID()

	insertUser := unitTestUserGenerator("InsertNewUser-One")
	insertUser.Uuid = uuid1
	insertUser.IsVerified = true

	// invalid - duplicate uuid
	insertUser1 := unitTestUserGenerator(unitTestFailValue)
	insertUser1.Uuid = uuid1
	insertUser1.IsVerified = true

	// invalid - duplicate email
	insertUser2 := unitTestUserGenerator(unitTestFailValue)
	insertUser2.Uuid = uuid2
	insertUser2.Email = insertUser.GetEmail()
	insertUser2.IsVerified = true

	// invalid - first name
	insertUser3 := &pblib.User{
		Uuid:      uuid2,
		FirstName: "",
	}

	// invalid - last name
	insertUser4 := &pblib.User{
		Uuid:      uuid2,
		FirstName: unitTestFailValue,
		LastName:  "",
	}

	// invalid - email
	insertUser5 := &pblib.User{
		Uuid:      uuid2,
		FirstName: unitTestFailValue,
		LastName:  unitTestFailValue,
		Email:     "@",
	}

	// invalid - password
	insertUser6 := &pblib.User{
		Uuid:      uuid2,
		FirstName: unitTestFailValue,
		LastName:  unitTestFailValue,
		Email:     unitTestFailEmail,
		Password:  "",
	}

	// invalid - organization
	insertUser7 := &pblib.User{
		Uuid:         uuid2,
		FirstName:    unitTestFailValue,
		LastName:     unitTestFailValue,
		Email:        unitTestFailEmail,
		Password:     unitTestFailValue,
		Organization: "",
	}

	cases := []struct {
		user     *pblib.User
		isExpErr bool
		expMsg   string
		desc     string
	}{
		{insertUser, false, "", "test valid user insert"},
		{insertUser1, true, "pq: duplicate key value violates unique constraint \"accounts_pkey\"", "test duplicate uuid"},
		{insertUser2, true, "pq: duplicate key value violates unique constraint \"accounts_email_key\"", "test duplicate email"},
		{insertUser3, true, consts.ErrInvalidUserFirstName.Error(), "test invalid first name"},
		{insertUser4, true, consts.ErrInvalidUserLastName.Error(), "test invalid last name"},
		{insertUser5, true, consts.ErrInvalidUserEmail.Error(), "test invalid email"},
		{insertUser6, true, consts.ErrInvalidPassword.Error(), "test invalid password"},
		{insertUser7, true, consts.ErrInvalidUserOrganization.Error(), "test invalid organization"},
		{nil, true, consts.ErrNilRequestUser.Error(), "test nil request user"},
		{&pblib.User{}, true, authconst.ErrInvalidUUID.Error(), "test nil user object"},
		{&pblib.User{Uuid: "1234"}, true, authconst.ErrInvalidUUID.Error(), "test invalid uuid form"},
	}

	for _, c := range cases {
		err := insertNewUser(c.user)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg, c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestInsertEmailToken(t *testing.T) {
	user1, err := unitTestInsertUser("InsertEmailToken-One")
	assert.Nil(t, err)
	user2, err := unitTestInsertUser("InsertEmailToken-Two")
	assert.Nil(t, err)
	err = deleteEmailTokenRow(user1.GetUser().GetUuid())
	assert.Nil(t, err)
	err = deleteEmailTokenRow(user2.GetUser().GetUuid())
	assert.Nil(t, err)

	validID1, err := generateEmailToken(user1.GetUser().GetUuid(), user1.GetUser().GetPermissionLevel())
	assert.Nil(t, err)
	assert.NotNil(t, validID1)

	desc := "empty uuid"
	err = insertEmailToken("", validID1.GetToken(), validID1.GetSecret())
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error(), desc)

	desc = "invalid uuid format"
	err = insertEmailToken("1234", validID1.GetToken(), validID1.GetSecret())
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error(), desc)

	desc = "empty token"
	err = insertEmailToken(user1.GetUser().GetUuid(), "", validID1.GetSecret())
	assert.EqualError(t, err, authconst.ErrEmptyToken.Error(), desc)

	desc = "valid uuid and valid token"
	err = insertEmailToken(user1.GetUser().GetUuid(), validID1.GetToken(), validID1.GetSecret())
	assert.Nil(t, err, desc)

	desc = "test duplicate uuid in user_svc.email_tokens table"
	err = insertEmailToken(user1.GetUser().GetUuid(), "some token", validID1.GetSecret())
	assert.EqualError(t, err, "pq: duplicate key value violates unique constraint \"email_tokens_uuid_key\"", desc)

	desc = "test non-existent uuid"
	nonExistentUUID, _ := generateUUID()
	err = insertEmailToken(nonExistentUUID, "some token", validID1.GetSecret())
	assert.EqualError(t, err, "pq: insert or update on table \"email_tokens\" violates foreign key constraint \"email_tokens_uuid_fkey\"", desc)

	desc = "test duplicate token"
	err = insertEmailToken(user2.GetUser().GetUuid(), validID1.GetToken(), validID1.GetSecret())
	assert.EqualError(t, err, "pq: duplicate key value violates unique constraint \"email_tokens_pkey\"", desc)

	desc = "test nil secret"
	err = insertEmailToken(user2.GetUser().GetUuid(), validID1.GetToken(), nil)
	assert.EqualError(t, err, authconst.ErrNilSecret.Error(), desc)

}

func TestDeleteUserRow(t *testing.T) {
	response, err := unitTestInsertUser("DeleteUserRow-One")
	assert.Nil(t, err)

	err = deleteUserRow("")
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error())

	err = deleteUserRow("1234")
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error())

	err = deleteUserRow(response.GetUser().GetUuid())
	assert.Nil(t, err)

	// non existent (db does not throw an error)
	err = deleteUserRow(response.GetUser().GetUuid())
	assert.Nil(t, err)
}

func TestGetUserRow(t *testing.T) {
	// non existent uuid
	nonExistentUUID, _ := generateUUID()
	retrievedUser, err := getUserRow(nonExistentUUID)
	assert.EqualError(t, err, consts.ErrUserNotFound.Error())
	assert.Nil(t, retrievedUser)

	// existent uuid
	response, err := unitTestInsertUser("GetUserRow-One")
	assert.Nil(t, err)

	retrievedUser, err = getUserRow(response.GetUser().GetUuid())
	assert.Nil(t, err)
	assert.Equal(t, response.GetUser().GetUuid(), retrievedUser.GetUuid())
	assert.Equal(t, response.GetUser().GetFirstName(), retrievedUser.GetFirstName())
	assert.Equal(t, response.GetUser().GetLastName(), retrievedUser.GetLastName())
	assert.Equal(t, response.GetUser().GetEmail(), retrievedUser.GetEmail())
	assert.Equal(t, response.GetUser().GetOrganization(), retrievedUser.GetOrganization())
}

func TestUpdateUserRow(t *testing.T) {
	// insert some new users
	response1, err := unitTestInsertUser("UpdateUserRow-One")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response1.GetMessage())
	response1.GetUser().IsVerified = true

	response2, err := unitTestInsertUser("UpdateUserRow-Two")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response2.GetMessage())
	err = deleteEmailTokenRow(response2.GetUser().GetUuid())
	assert.Nil(t, err)
	response2.GetUser().IsVerified = true

	// update firstname and modified_date
	svc := &pblib.User{
		FirstName: response1.GetUser().GetFirstName() + " UPDATED",
		Uuid:      response1.GetUser().GetUuid(),
	}

	// update prospective_email, is_verified, modified_date
	newEmail := unitTestEmailGenerator()
	svc2 := &pblib.User{
		Email: newEmail,
		Uuid:  response2.GetUser().GetUuid(),
	}

	// invalid - update prospective_email with an EXISTING email
	svc3 := &pblib.User{
		Email: response2.GetUser().GetEmail(),
		Uuid:  response1.GetUser().GetUuid(),
	}

	// invalid - update prosptive_email with a EXISTING prospective_email
	svc4 := &pblib.User{
		Email: newEmail,
		Uuid:  response1.GetUser().GetUuid(),
	}

	nonExistentUUID, _ := generateUUID()

	cases := []struct {
		uuid       string
		svcDerived *pblib.User
		dbDerived  *pblib.User
		isExpErr   bool
		expMsg     string
	}{
		{"", nil, nil, true, consts.ErrNilRequestUser.Error()},
		{nonExistentUUID, nil, nil, true, consts.ErrNilRequestUser.Error()},
		{nonExistentUUID, &pblib.User{}, nil, true,
			consts.ErrNilRequestUser.Error()},
		{nonExistentUUID, &pblib.User{}, &pblib.User{}, true,
			consts.ErrEmptyRequestUser.Error()},
		{nonExistentUUID, &pblib.User{FirstName: "@"}, &pblib.User{}, true,
			consts.ErrInvalidUserFirstName.Error()},
		{nonExistentUUID, &pblib.User{LastName: "@"}, &pblib.User{}, true,
			consts.ErrInvalidUserLastName.Error()},
		{nonExistentUUID, &pblib.User{Email: "@"}, &pblib.User{}, true,
			consts.ErrInvalidUserEmail.Error()},
		{svc.Uuid, svc, response1.GetUser(), false, ""},
		{svc2.Uuid, svc2, response2.GetUser(), false, ""},
		{svc3.Uuid, svc3, response1.GetUser(), true, consts.ErrEmailExists.Error()},
		{svc4.Uuid, svc4, response1.GetUser(), true, consts.ErrEmailExists.Error()},
	}

	for _, c := range cases {
		updatedUser, err := updateUserRow(c.uuid, c.svcDerived, c.dbDerived)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
			assert.Nil(t, updatedUser)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.uuid, updatedUser.GetUuid())
		}
	}

	//TODO test for new insertion of token for new email updates
}

func TestGetActiveSecretRow(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	// test empty row
	retrievedSecret, err := getActiveSecretRow()
	assert.EqualError(t, err, consts.ErrNoActiveSecretKeyFound.Error())
	assert.Nil(t, retrievedSecret)

	// insert a key to test for active key retrieval
	err = insertNewAuthSecret()
	assert.Nil(t, err)

	retrievedSecret, err = getActiveSecretRow()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)
	assert.NotEmpty(t, retrievedSecret.Key)
	assert.NotEmpty(t, retrievedSecret.CreatedTimestamp)
	assert.NotEmpty(t, retrievedSecret.ExpirationTimestamp)
}

func TestInsertNewSecret(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	err = insertNewAuthSecret()
	assert.Nil(t, err)

	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)

	// test that key was inserted
	secretKey, err := getLatestSecret(2)
	assert.Nil(t, err)
	assert.Equal(t, retrievedSecret.GetKey(), secretKey)
}

func TestGetLatestSecret(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	err = insertNewAuthSecret()
	assert.Nil(t, err)

	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)

	secretKey, err := getLatestSecret(2)
	assert.Nil(t, err)
	assert.Equal(t, retrievedSecret.GetKey(), secretKey)

	secretKey, err = getLatestSecret(0)
	assert.EqualError(t, err, consts.ErrInvalidAddTime.Error())
	assert.Empty(t, secretKey)

}

func TestInsertAuthToken(t *testing.T) {
	token := "someToken"

	// retrieve freshly active secret
	retrievedSecret, err := unitTestDeleteInsertGetAuthSecret()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)
	currAuthSecret = retrievedSecret

	// the above happens so fast that validating secret creation time fails b/c time == now()
	time.Sleep(2 * time.Second)

	uuid, err := generateUUID()
	assert.Nil(t, err)
	validTokenBody.UUID = uuid

	cases := []struct {
		body     *auth.Body
		secret   *pblib.Secret
		header   *auth.Header
		token    string
		isExpErr bool
		expMsg   string
	}{
		// valid
		{validTokenBody, currAuthSecret, validTokenHeader, token, false, ""},
		// empty token
		{validTokenBody, currAuthSecret, validTokenHeader, "", true, authconst.ErrEmptyToken.Error()},
		// nil header
		{validTokenBody, currAuthSecret, nil, token, true, authconst.ErrNilHeader.Error()},
		// nil body
		{nil, currAuthSecret, validTokenHeader, token, true, authconst.ErrNilBody.Error()},
		// nil secret
		{validTokenBody, nil, validTokenHeader, token, true, authconst.ErrNilSecret.Error()},
		// body contains invalid UUID
		{
			&auth.Body{
				UUID:                "invalid",
				Permission:          validTokenBody.Permission,
				ExpirationTimestamp: validTokenBody.ExpirationTimestamp,
			}, currAuthSecret, validTokenHeader, token, true, authconst.ErrInvalidUUID.Error(),
		},
		// body contains invalid timestamp
		{
			&auth.Body{
				UUID:                validTokenBody.UUID,
				Permission:          validTokenBody.Permission,
				ExpirationTimestamp: 12,
			}, currAuthSecret, validTokenHeader, token, true, authconst.ErrExpiredBody.Error(),
		},
		// secret contains empty secret Key
		{
			validTokenBody,
			&pblib.Secret{
				Key:                 "",
				CreatedTimestamp:    currAuthSecret.CreatedTimestamp,
				ExpirationTimestamp: currAuthSecret.ExpirationTimestamp,
			}, validTokenHeader, token, true, authconst.ErrEmptySecret.Error(),
		},
		// secret contains createTimestamp greater than now
		{
			validTokenBody,
			&pblib.Secret{
				Key:                 currAuthSecret.Key,
				CreatedTimestamp:    currAuthSecret.ExpirationTimestamp,
				ExpirationTimestamp: currAuthSecret.ExpirationTimestamp,
			}, validTokenHeader, token, true, authconst.ErrInvalidSecretCreateTimestamp.Error(),
		},
		// secret contains invalid expirationTimestamp
		{
			validTokenBody,
			&pblib.Secret{
				Key:                 currAuthSecret.Key,
				CreatedTimestamp:    currAuthSecret.CreatedTimestamp,
				ExpirationTimestamp: 12,
			}, validTokenHeader, token, true, authconst.ErrExpiredSecret.Error(),
		},
	}

	for _, c := range cases {
		err := insertAuthToken(c.token, c.header, c.body, c.secret)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetNewAuthTokenRow(t *testing.T) {
	retrievedSecret, err := unitTestDeleteInsertGetAuthSecret()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)

	validUUID, err := generateUUID()
	assert.Nil(t, err)
	assert.NotEmpty(t, validUUID)

	cases := []struct {
		desc     string
		uuid     string
		isExpErr bool
		expMsg   string
	}{
		{"test valid, non existing user", validUUID, true, consts.ErrNoAuthTokenFound.Error()},
		{"test empty uuid", "", true, authconst.ErrInvalidUUID.Error()},
		{"test invalid uuid form", "invalid", true, authconst.ErrInvalidUUID.Error()},
	}

	for _, c := range cases {
		retrievedToken, err := getAuthTokenRow(c.uuid)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg, c.desc)
			assert.Nil(t, retrievedToken, c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Nil(t, retrievedToken, c.desc)
		}
	}

	// test valid with existing user
	validTokenBody.UUID = validUUID
	// the above happens so fast that validating secret creation time fails b/c time == now()
	time.Sleep(2 * time.Second)
	err = insertAuthToken("TestRetrieveExistingToken", validTokenHeader, validTokenBody, retrievedSecret)
	assert.Nil(t, err)

	retrievedToken, err := getAuthTokenRow(validUUID)
	assert.Nil(t, err)
	assert.NotEmpty(t, retrievedToken.uuid)
	assert.NotEmpty(t, retrievedToken.token)
	assert.NotEmpty(t, retrievedToken.permission)
	assert.NotEmpty(t, retrievedToken.secret.Key)
	assert.NotEmpty(t, retrievedToken.secret.ExpirationTimestamp)
	assert.NotEmpty(t, retrievedToken.secret.CreatedTimestamp)
}

func TestPairTokenWithSecret(t *testing.T) {
	desc := "test empty token"
	retrievedSecret, err := pairTokenWithSecret("")
	assert.EqualError(t, err, authconst.ErrEmptyToken.Error(), desc)
	assert.Nil(t, retrievedSecret, desc)

	desc = "test non-existing token"
	retrievedSecret, err = pairTokenWithSecret("non-existing-token")
	assert.EqualError(t, err, consts.ErrNoMatchingAuthTokenFound.Error(), desc)
	assert.Nil(t, retrievedSecret, desc)

	newSecret, newToken, err := unitTestInsertNewAuthToken()
	assert.Nil(t, err)
	assert.NotNil(t, newSecret)
	assert.NotEmpty(t, newToken)

	desc = "test against existing token"
	retrievedSecret, err = pairTokenWithSecret(newToken)
	assert.Nil(t, err, desc)
	assert.NotEmpty(t, retrievedSecret, desc)
	assert.Equal(t, newSecret.Key, retrievedSecret.GetSecret().GetKey(), desc)
	assert.Equal(t, newSecret.CreatedTimestamp, retrievedSecret.GetSecret().GetCreatedTimestamp(), desc)
	assert.Equal(t, newSecret.ExpirationTimestamp, retrievedSecret.GetSecret().GetExpirationTimestamp(), desc)
}

func TestHasActiveSecret(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	desc := "test with no active secret in table"
	exists, err := hasActiveAuthSecret()
	assert.Nil(t, err, desc)
	assert.Equal(t, false, exists, desc)

	desc = "test with an active secret in table"
	err = insertNewAuthSecret()
	assert.Nil(t, err)
	exists, err = hasActiveAuthSecret()
	assert.Nil(t, err, desc)
	assert.Equal(t, true, exists, desc)
}

func TestActiveSecretTrigger(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	time.Sleep(10 * time.Second)
	err = insertNewAuthSecret()
	assert.Nil(t, err)
	time.Sleep(10 * time.Second)
	err = insertNewAuthSecret()
	assert.Nil(t, err)
	time.Sleep(10 * time.Second)
	err = insertNewAuthSecret()
	assert.Nil(t, err)

	exists, err := hasActiveAuthSecret()
	assert.Nil(t, err)
	assert.Equal(t, true, exists)

	secretKey, err := getLatestSecret(5)
	assert.Nil(t, err)
	assert.NotEmpty(t, secretKey)

	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.Equal(t, retrievedSecret.GetKey(), secretKey)
}

func TestIsEmailTaken(t *testing.T) {
	// create a user to test with
	user1, err := unitTestInsertUser("IsEmailTaken-One")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), user1.GetMessage())

	// update prospective_email for user1
	newEmail := unitTestEmailGenerator()
	svcDerived := &pblib.User{
		Email: newEmail,
		Uuid:  user1.GetUser().GetUuid(),
	}
	// update user1's email
	updatedUser, err := updateUserRow(user1.GetUser().GetUuid(), svcDerived, user1.GetUser())
	assert.Nil(t, err)
	assert.NotNil(t, updatedUser)

	cases := []struct {
		desc         string
		email        string
		isEmailTaken bool
		isExpErr     bool
		expMsg       string
	}{
		{"test an existing prospective email", newEmail, true, false, ""},
		{"test an existing email in db", user1.GetUser().GetEmail(), true, false, ""},
		{"test non-existent email in db", "test-is-email-taken@unit-test.com", false, false, ""},
		{"test invalid email format", "@", false, true, consts.ErrInvalidUserEmail.Error()},
		{"test empty email string", "", false, true, consts.ErrInvalidUserEmail.Error()},
	}

	for _, c := range cases {
		emailTaken, err := isEmailTaken(c.email)
		if c.isExpErr {
			assert.EqualError(t, err, consts.ErrInvalidUserEmail.Error(), c.desc)
			assert.Equal(t, false, emailTaken, c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			if c.isEmailTaken {
				assert.Equal(t, true, emailTaken, c.desc)
			} else {
				assert.Equal(t, false, emailTaken, c.desc)
			}
		}
	}
}

func TestGetEmailTokenRow(t *testing.T) {
	// create a user to insert a token to its uuid
	user1, err := unitTestInsertUser("GetExistingEmailToken-One")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), user1.GetMessage())

	err = deleteEmailTokenRow(user1.GetUser().GetUuid())
	assert.Nil(t, err)

	emailID, err := generateEmailToken(user1.GetUser().GetUuid(), user1.GetUser().GetPermissionLevel())
	assert.Nil(t, err)
	assert.NotNil(t, emailID)

	// insert token
	err = insertEmailToken(user1.GetUser().GetUuid(), emailID.GetToken(), emailID.GetSecret())
	assert.Nil(t, err)

	cases := []struct {
		desc     string
		token    string
		isExpErr bool
		expMsg   string
	}{
		{"test existing token", emailID.GetToken(), false, ""},
		{"test empty token string", "", true, authconst.ErrEmptyToken.Error()},
		{"test non-existing token", "1234abc", true, consts.ErrNoMatchingEmailTokenFound.Error()},
	}

	for _, c := range cases {
		retrievedRow, err := getEmailTokenRow(c.token)

		if c.isExpErr {
			assert.Nil(t, retrievedRow, c.desc)
			assert.EqualError(t, err, c.expMsg, c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, retrievedRow.token, emailID.GetToken(), c.desc)
		}
	}
}

func TestDeleteEmailTokenRow(t *testing.T) {
	// create a user to insert a token
	user1, err := unitTestInsertUser("DeleteEmailTokenRow-One")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), user1.GetMessage())

	testUUID, err := generateUUID()
	assert.Nil(t, err)
	assert.NotEmpty(t, testUUID)

	cases := []struct {
		desc     string
		uuid     string
		isExpErr bool
		expMsg   string
	}{
		{"test with existing valid uuid", user1.GetUser().GetUuid(), false, ""},
		{"test with a non-existing valid uuid", testUUID, false, ""},
		{"test with invalid uuid format", "1234", true, authconst.ErrInvalidUUID.Error()},
	}

	for _, c := range cases {
		err := deleteEmailTokenRow(c.uuid)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg, c.desc)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestMatchEmailAndPassword(t *testing.T) {
	// create a user
	user1Password := "TestMatchEmailAndPassword-One"
	user1, err := unitTestInsertUser(user1Password)
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), user1.GetMessage())
	u1 := user1.GetUser()

	cases := []struct {
		desc     string
		email    string
		password string
		isExpErr bool
		expMsg   string
	}{
		{
			"test empty email", "", unitTestFailValue,
			true, consts.ErrInvalidUserEmail.Error(),
		},
		{
			"test invalid email format", "@", unitTestFailValue,
			true, consts.ErrInvalidUserEmail.Error(),
		},
		{
			"test existing email but empty password", u1.GetEmail(), "",
			true, consts.ErrInvalidPassword.Error(),
		},
		{
			"test valid password but non-existent email", unitTestFailEmail, user1Password,
			true, consts.ErrEmailDoesNotExist.Error(),
		},
		{
			"test existing email but non-existent password", u1.GetEmail(), unitTestFailValue,
			true, "crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			"valid, test existing email and matching password", u1.GetEmail(), user1Password,
			false, "",
		},
	}

	for _, c := range cases {
		retrievedUser, err := matchEmailAndPassword(c.email, c.password)
		if c.isExpErr {
			assert.Nil(t, retrievedUser, c.desc)
			assert.EqualError(t, err, c.expMsg, c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, u1.GetEmail(), retrievedUser.GetEmail(), c.desc)
			assert.Equal(t, u1.GetUuid(), retrievedUser.GetUuid(), c.desc)
		}
	}

}

func TestUpdatePermissionLevel(t *testing.T) {
	// create a test user
	user1, err := unitTestInsertUser("TestUpdatePermissionLevel")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), user1.GetMessage())
	u1 := user1.GetUser()
	assert.Equal(t, auth.PermissionStringMap[auth.NoPermission], u1.GetPermissionLevel())

	uuid, err := generateUUID()
	assert.Nil(t, err)

	cases := []struct {
		desc      string
		uuid      string
		permLevel string
		isExpErr  bool
		expMsg    string
	}{
		{
			"test valid uuid, but not existing in db", uuid, auth.PermissionStringMap[auth.User],
			false, "",
		},
		{
			"test invalid uuid", unitTestFailValue, "", true,
			authconst.ErrInvalidUUID.Error(),
		},
		{
			"test blank uuid", "", "", true,
			authconst.ErrInvalidUUID.Error(),
		},
		{
			"test invalid permLevel", u1.GetUuid(), "unitTestFailValue", true,
			authconst.ErrInvalidPermission.Error(),
		},
		{
			"test blank permLevel", u1.GetUuid(), "", true,
			authconst.ErrInvalidPermission.Error(),
		},
		{
			"test valid uuid and permLevel", u1.GetUuid(), auth.PermissionStringMap[auth.User],
			false, "",
		},
	}

	for _, c := range cases {
		err := updatePermissionLevel(c.uuid, c.permLevel)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg, c.desc)
		} else {
			assert.Nil(t, err, c.desc)

			retrievedUser, err := getUserRow(c.uuid)
			if err == nil {
				assert.Equal(t, c.permLevel, retrievedUser.GetPermissionLevel())
			}
		}
	}
}
