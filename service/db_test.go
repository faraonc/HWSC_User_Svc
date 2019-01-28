package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/stretchr/testify/assert"
	"testing"
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
	insertUser := &pb.User{
		Uuid:         "1111xsnjg0mqjhbf4qx1efd6y7",
		FirstName:    "Test",
		LastName:     "Insert New User",
		Email:        "unit@test.com",
		Password:     "unit_testing",
		Organization: "Unit Testing",
		IsVerified:   true,
	}

	// invalid - duplicate uuid
	insertUser1 := &pb.User{
		Uuid:         "1111xsnjg0mqjhbf4qx1efd6y7",
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "unit@test.com",
		Password:     "123456789",
		Organization: "lisa",
		IsVerified:   true,
	}

	// invalid - duplicate email
	insertUser2 := &pb.User{
		Uuid:         "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "unit@test.com",
		Password:     "123456789",
		Organization: "lisa",
		IsVerified:   true,
	}

	// invalid - first name
	insertUser3 := &pb.User{
		Uuid:      "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName: "",
	}

	// invalid - last name
	insertUser4 := &pb.User{
		Uuid:      "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName: "Lisa",
		LastName:  "",
	}

	// invalid - email
	insertUser5 := &pb.User{
		Uuid:      "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName: "Lisa",
		LastName:  "Kim",
		Email:     "@",
	}

	// invalid - password
	insertUser6 := &pb.User{
		Uuid:      "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName: "Lisa",
		LastName:  "Kim",
		Email:     "unit@test.com",
		Password:  "",
	}

	// invalid - organization
	insertUser7 := &pb.User{
		Uuid:         "2222xsnjg0mqjhbf4qx1efd6y8",
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "unit@test.com",
		Password:     "123455677",
		Organization: "",
	}

	cases := []struct {
		user     *pb.User
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
		{&pb.User{}, true, consts.ErrInvalidUUID.Error()},
		{&pb.User{Uuid: "1234"}, true, consts.ErrInvalidUUID.Error()},
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

func TestInsertToken(t *testing.T) {
	err := insertToken("")
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	err = insertToken("1234")
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	err = insertToken("0000xsnjg0mqjhbf4qx1efd6y6")
	assert.Nil(t, err)

	// test duplicate uuid in user_svc.pending_tokens table
	err = insertToken("0000xsnjg0mqjhbf4qx1efd6y6")
	assert.EqualError(t, err, "pq: duplicate key value violates unique constraint \"pending_tokens_uuid_key\"")

	// test non-existent uuid
	err = insertToken("1111xsnjg0mqjhbf4qx1efd6y9")
	assert.EqualError(t, err, "pq: insert or update on table \"pending_tokens\" violates foreign key constraint \"pending_tokens_uuid_fkey\"")
}

func TestCheckUserExists(t *testing.T) {
	exists, err := checkUserExists("")
	assert.Equal(t, false, exists)
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	exists, err = checkUserExists("1234")
	assert.Equal(t, false, exists)
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	exists, err = checkUserExists("0000xsnjg0mqjhbf4qx1efd6y4")
	assert.Equal(t, true, exists)
	assert.Nil(t, err)

	exists, err = checkUserExists("1111xsnjg0mqjhbf4qx1efd6y9")
	assert.Equal(t, false, exists)
	assert.Nil(t, err)
}

func TestDeleteUserRow(t *testing.T) {
	err := deleteUserRow("")
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	err = deleteUserRow("1234")
	assert.EqualError(t, err, consts.ErrInvalidUUID.Error())

	err = deleteUserRow("1000xsnjg0mqjhbf4qx1efd6y7")
	assert.Nil(t, err)

	// non existent (db does not throw an error)
	err = deleteUserRow("1000xsnjg0mqjhbf4qx1efd6y7")
	assert.Nil(t, err)
}

func TestGetUserRow(t *testing.T) {
	// non existent uuid
	user, err := getUserRow("1010asnjg0mqjhbf4qx1efd6y1")
	assert.EqualError(t, err, consts.ErrUUIDNotFound.Error())
	assert.Nil(t, user)

	// existent uuid
	existentUser := &pb.User{
		Uuid:         "1212asnjg0mqjhbf4qx1efd6y2",
		FirstName:    "Unit Test",
		LastName:     "GetUserRow",
		Email:        "get@user.com",
		Organization: "unit test getUserRow",
	}
	user, err = getUserRow(existentUser.GetUuid())
	assert.Nil(t, err)
	assert.Equal(t, existentUser.GetUuid(), user.GetUuid())
	assert.Equal(t, existentUser.GetFirstName(), user.GetFirstName())
	assert.Equal(t, existentUser.GetLastName(), user.GetLastName())
	assert.Equal(t, existentUser.GetEmail(), user.GetEmail())
	assert.Equal(t, existentUser.GetOrganization(), user.GetOrganization())
}

func TestUpdateUserRow(t *testing.T) {
	// update firstname and modified_date
	svc := &pb.User{
		FirstName: "Test Update User Row",
		Uuid:      "0000xsnjg0mqjhbf4qx1efd6y6",
	}
	db := &pb.User{
		FirstName:    "John F",
		LastName:     "Kennedy",
		Email:        "john@test.com",
		Organization: "123",
		IsVerified:   true,
	}

	// update prospective_email, is_verified, modified_date
	svc2 := &pb.User{
		Email: "updateUserRow@test.com",
		Uuid:  "0000xsnjg0mqjhbf4qx1efd6y5",
	}
	db2 := &pb.User{
		FirstName:    "Mary-Jo",
		LastName:     "Allen",
		Email:        "mary@test.com",
		Organization: "abc",
		IsVerified:   true,
	}

	const someID = "1111abcde0mqjhbf4qx1efd6y3"

	cases := []struct {
		uuid       string
		svcDerived *pb.User
		dbDerived  *pb.User
		isExpErr   bool
		expMsg     string
	}{
		{"", nil, nil, true, consts.ErrNilRequestUser.Error()},
		{someID, nil, nil, true, consts.ErrNilRequestUser.Error()},
		{someID, &pb.User{}, nil, true, consts.ErrNilRequestUser.Error()},
		{someID, &pb.User{}, &pb.User{}, true, consts.ErrEmptyRequestUser.Error()},
		{someID, &pb.User{FirstName: "@"}, &pb.User{}, true, consts.ErrInvalidUserFirstName.Error()},
		{someID, &pb.User{LastName: "@"}, &pb.User{}, true, consts.ErrInvalidUserLastName.Error()},
		{someID, &pb.User{Email: "@"}, &pb.User{}, true, consts.ErrInvalidUserEmail.Error()},
		{svc.Uuid, svc, db, false, ""},
		{svc2.Uuid, svc2, db2, false, ""},
	}

	for _, c := range cases {
		err := updateUserRow(c.uuid, c.svcDerived, c.dbDerived)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}
