package service

import (
	pblib "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"testing"
	"time"
)

func deleteSecretTable() error {
	_, err := postgresDB.Exec("DELETE FROM user_security.secret")
	return err
}

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
	}{
		{insertUser, false, ""},
		{insertUser1, true, "pq: duplicate key value violates unique constraint \"accounts_pkey\""},
		{insertUser2, true, "pq: duplicate key value violates unique constraint \"accounts_email_key\""},
		{insertUser3, true, consts.ErrInvalidUserFirstName.Error()},
		{insertUser4, true, consts.ErrInvalidUserLastName.Error()},
		{insertUser5, true, consts.ErrInvalidUserEmail.Error()},
		{insertUser6, true, consts.ErrInvalidPassword.Error()},
		{insertUser7, true, consts.ErrInvalidUserOrganization.Error()},
		{nil, true, consts.ErrNilRequestUser.Error()},
		{&pblib.User{}, true, authconst.ErrInvalidUUID.Error()},
		{&pblib.User{Uuid: "1234"}, true, authconst.ErrInvalidUUID.Error()},
	}

	for _, c := range cases {
		err := insertNewUser(c.user)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestInsertEmailToken(t *testing.T) {
	templateDirectory = unitTestEmailTemplateDirectory

	response, err := unitTestInsertUser("InsertEmailToken-One")
	assert.Nil(t, err)
	// TODO temporary
	err = unitTestRemovePendingToken(response.GetUser().GetUuid())
	assert.Nil(t, err)

	// invalid
	err = insertEmailToken("")
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error())

	// invalid
	err = insertEmailToken("1234")
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error())

	// valid
	err = insertEmailToken(response.GetUser().GetUuid())
	assert.Nil(t, err)

	// test duplicate uuid in user_svc.pending_tokens table
	err = insertEmailToken(response.GetUser().GetUuid())
	assert.EqualError(t, err, "pq: duplicate key value violates unique constraint \"pending_tokens_uuid_key\"")

	// test non-existent uuid
	nonExistentUUID, _ := generateUUID()
	err = insertEmailToken(nonExistentUUID)
	assert.EqualError(t, err, "pq: insert or update on table \"pending_tokens\" violates foreign key constraint \"pending_tokens_uuid_fkey\"")
}

func TestDeleteUserRow(t *testing.T) {
	templateDirectory = unitTestEmailTemplateDirectory

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
	templateDirectory = unitTestEmailTemplateDirectory

	// non existent uuid
	nonExistentUUID, _ := generateUUID()
	retrievedUser, err := getUserRow(nonExistentUUID)
	assert.EqualError(t, err, authconst.ErrInvalidUUID.Error())
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
	templateDirectory = unitTestEmailTemplateDirectory

	// insert some new users
	response1, err := unitTestInsertUser("UpdateUserRow-One")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response1.GetMessage())
	response1.GetUser().IsVerified = true

	response2, err := unitTestInsertUser("UpdateUserRow-Two")
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response2.GetMessage())
	err = unitTestRemovePendingToken(response2.GetUser().GetUuid())
	assert.Nil(t, err)
	response2.GetUser().IsVerified = true

	// update firstname and modified_date
	svc := &pblib.User{
		FirstName: response1.GetUser().GetFirstName() + " UPDATED",
		Uuid:      response1.GetUser().GetUuid(),
	}

	// update prospective_email, is_verified, modified_date
	svc2 := &pblib.User{
		Email: response2.GetUser().GetEmail() + "-UPDATED",
		Uuid:  response2.GetUser().GetUuid(),
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
}

func TestGetActiveSecretRow(t *testing.T) {
	err := deleteSecretTable()
	assert.Nil(t, err)

	// test empty row
	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.Nil(t, retrievedSecret)

	// insert a key to test for active key retrieval
	err = insertNewSecret()
	assert.Nil(t, err)

	retrievedSecret, err = getActiveSecretRow()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)
	assert.NotEmpty(t, retrievedSecret.Key)
	assert.NotEmpty(t, retrievedSecret.CreatedTimestamp)
	assert.NotEmpty(t, retrievedSecret.ExpirationTimestamp)
}

func TestDeactivateSecret(t *testing.T) {
	err := deleteSecretTable()
	assert.Nil(t, err)

	// test empty string
	err = deactivateSecret("")
	assert.Nil(t, err)

	// test non existing key
	nonExistingSecret, err := generateSecretKey(auth.SecretByteSize)
	assert.Nil(t, err)
	assert.NotEmpty(t, nonExistingSecret)

	err = deactivateSecret(nonExistingSecret)
	assert.Nil(t, err)

	// test existing key
	err = insertNewSecret()
	assert.Nil(t, err)

	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)

	err = deactivateSecret(retrievedSecret.GetKey())
	assert.Nil(t, err)

	// test there are no active keys
	retrievedSecret, err = getActiveSecretRow()
	assert.Nil(t, err)
	assert.Nil(t, retrievedSecret)
}

func TestInsertNewSecret(t *testing.T) {
	err := deleteSecretTable()
	assert.Nil(t, err)

	err = insertNewSecret()
	assert.Nil(t, err)

	// test that key was inserted
	found, err := queryLatestSecret(2)
	assert.Nil(t, err)
	assert.Equal(t, true, found)
}

func TestQueryLatestSecret(t *testing.T) {
	err := deleteSecretTable()
	assert.Nil(t, err)

	err = insertNewSecret()
	assert.Nil(t, err)

	found, err := queryLatestSecret(0)
	assert.EqualError(t, err, consts.ErrInvalidAddTime.Error())
	assert.Equal(t, false, found)

	found, err = queryLatestSecret(2)
	assert.Nil(t, err)
	assert.Equal(t, true, found)
}

func TestInsertJWToken(t *testing.T) {
	token := "someToken"

	err := deleteSecretTable()
	assert.Nil(t, err)

	// insert fresh secret
	err = insertNewSecret()
	assert.Nil(t, err)

	// retrieve freshly active secret
	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)
	currSecret = retrievedSecret

	// the above happens so fast that validating secret creation time fails b/c time == now()
	time.Sleep(2 * time.Second)

	validHeader := &auth.Header{
		Alg:      auth.Hs256,
		TokenTyp: auth.Jwt,
	}

	uuid, err := generateUUID()
	assert.Nil(t, err)
	validBody := &auth.Body{
		UUID:                uuid,
		Permission:          auth.User,
		ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(jwtExpirationTime)).Unix(),
	}

	cases := []struct {
		body     *auth.Body
		secret   *pblib.Secret
		header   *auth.Header
		token    string
		isExpErr bool
		expMsg   string
	}{
		// valid
		{validBody, currSecret, validHeader, token, false, ""},
		// empty token
		{validBody, currSecret, validHeader, "", true, authconst.ErrEmptyToken.Error()},
		// nil header
		{validBody, currSecret, nil, token, true, authconst.ErrNilHeader.Error()},
		// nil body
		{nil, currSecret, validHeader, token, true, authconst.ErrNilBody.Error()},
		// nil secret
		{validBody, nil, validHeader, token, true, authconst.ErrNilSecret.Error()},
		// body contains invalid UUID
		{
			&auth.Body{
				UUID:                "invalid",
				Permission:          validBody.Permission,
				ExpirationTimestamp: validBody.ExpirationTimestamp,
			}, currSecret, validHeader, token, true, authconst.ErrInvalidUUID.Error(),
		},
		// body contains invalid timestamp
		{
			&auth.Body{
				UUID:       validBody.UUID,
				Permission: validBody.Permission,
				ExpirationTimestamp: 12,
			}, currSecret, validHeader, token, true, authconst.ErrExpiredBody.Error(),
		},
		// secret contains empty secret Key
		{
			validBody,
			&pblib.Secret{
				Key:                 "",
				CreatedTimestamp:    currSecret.CreatedTimestamp,
				ExpirationTimestamp: currSecret.ExpirationTimestamp,
			}, validHeader, token, true, authconst.ErrEmptySecret.Error(),
		},
		// secret contains createTimestamp greater than now
		{
			validBody,
			&pblib.Secret{
				Key:                 currSecret.Key,
				CreatedTimestamp:    currSecret.ExpirationTimestamp,
				ExpirationTimestamp: currSecret.ExpirationTimestamp,
			}, validHeader, token, true, authconst.ErrInvalidSecretCreateTimestamp.Error(),
		},
		// secret contains invalid expirationTimestamp
		{
			validBody,
			&pblib.Secret{
				Key:              currSecret.Key,
				CreatedTimestamp: currSecret.CreatedTimestamp,
				ExpirationTimestamp: 12,
			}, validHeader, token, true, authconst.ErrExpiredSecret.Error(),
		},
	}

	for _, c := range cases {
		err := insertJWToken(c.token, c.header, c.body, c.secret)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}
