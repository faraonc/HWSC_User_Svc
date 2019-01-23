package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
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

}

func TestInsertToken(t *testing.T) {

}

func TestCheckUserExists(t *testing.T) {

}

// need to rename this to deleteUserRow
//func TestDeleteUser(t *testing.T) {
//
//}

func TestGetUserRow(t *testing.T) {

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

	cases := []struct {
		uuid       string
		svcDerived *pb.User
		dbDerived  *pb.User
		isExpErr   bool
		expMsg     string
	}{
		{"", nil, nil, true, "invalid User uuid"},
		{"someid", nil, nil, true, "nil request User"},
		{"someid", &pb.User{}, nil, true, "nil request User"},
		{"someid", &pb.User{}, &pb.User{}, true, "empty request User"},
		{"someid", &pb.User{FirstName: "@"}, &pb.User{}, true, "invalid User first name"},
		{"someid", &pb.User{LastName: "@"}, &pb.User{}, true, "invalid User last name"},
		{"someid", &pb.User{Email: "@"}, &pb.User{}, true, "invalid User email"},
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
