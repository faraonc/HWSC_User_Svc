package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"testing"
)

func TestGetStatus(t *testing.T) {
	// test service state locker
	cases := []struct {
		request     *pb.UserRequest
		serverState state
		expMsg      string
	}{
		{&pb.UserRequest{}, available, codes.OK.String()},
		{&pb.UserRequest{}, unavailable, codes.Unavailable.String()},
	}

	for _, c := range cases {
		serviceStateLocker.currentServiceState = c.serverState
		s := Service{}
		response, _ := s.GetStatus(context.TODO(), c.request)
		assert.Equal(t, c.expMsg, response.GetMessage())
	}

	serviceStateLocker.currentServiceState = available
	s := Service{}

	// test refreshDBConnection
	err := postgresDB.Close()
	assert.Nil(t, err)

	response, _ := s.GetStatus(context.TODO(), &pb.UserRequest{})
	assert.Equal(t, codes.Unavailable.String(), response.GetMessage())

	// reconnect
	err = refreshDBConnection()
	assert.Nil(t, err)
}

func TestCreateUser(t *testing.T) {
	templateDirectory = "../tmpl/"
	// valid
	testUser1 := &pb.User{
		FirstName:    "Stella Lilly",
		LastName:     "Kim",
		Email:        "hwsc.test+user1@gmail.com",
		Password:     "12345678",
		Organization: "Test User 1",
	}

	// valid
	testUser2 := &pb.User{
		FirstName:    "Ray",
		LastName:     "Bradbury",
		Email:        "hwsc.test+user2@gmail.com",
		Password:     "12345678",
		Organization: "Test User 2",
	}

	// fail: duplicate email test
	testUser3 := &pb.User{
		FirstName:    "Duplicate Email",
		LastName:     "Test",
		Email:        "hwsc.test+user2@gmail.com",
		Password:     "12345678",
		Organization: "Test User 3",
	}

	// fail: invalid fields in userobject (it will fail on firstname)
	testUser4 := &pb.User{
		FirstName: "",
	}

	// fail: empty password
	testUser5 := &pb.User{
		FirstName: "Lisa",
		LastName:  "Kim",
		Email:     "hwsc.test+user3@gmail.com",
		Password:  "",
	}

	// fail: passwords with leading/trailing spaces
	testUser6 := &pb.User{
		FirstName: "Lisa",
		LastName:  "Kim",
		Email:     "hwsc.test+user3@gmail.com",
		Password:  "    abcklajdsfasdf      ",
	}

	// fail: blank email
	testUser7 := &pb.User{
		FirstName: "Blank",
		LastName:  "Email",
		Email:     "",
	}

	// fail: blank organization
	testUser8 := &pb.User{
		FirstName:    "Blank",
		LastName:     "Organization",
		Email:        "hwsc.test+user2@gmail.com",
		Password:     "12345678",
		Organization: "",
	}

	// fail: blank last name
	testUser9 := &pb.User{
		FirstName: "Lisa",
		LastName:  "",
	}

	cases := []struct {
		request  *pb.UserRequest
		isExpErr bool
		expMsg   string
	}{
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{}, true, "rpc error: code = InvalidArgument " +
			"desc = nil request User"},
		{&pb.UserRequest{User: testUser1}, false, codes.OK.String()},
		{&pb.UserRequest{User: testUser2}, false, codes.OK.String()},
		{&pb.UserRequest{User: testUser3}, true, "rpc error: code = " +
			"Internal desc = pq: duplicate key value violates unique constraint \"accounts_email_key\""},
		{&pb.UserRequest{User: testUser4}, true, "rpc error: code = " +
			"Internal desc = invalid User first name"},
		{&pb.UserRequest{User: testUser5}, true, "rpc error: code = " +
			"Internal desc = invalid User password"},
		{&pb.UserRequest{User: testUser6}, true, "rpc error: code = " +
			"Internal desc = invalid User password"},
		{&pb.UserRequest{User: testUser7}, true, "rpc error: code = " +
			"Internal desc = invalid User email"},
		{&pb.UserRequest{User: testUser8}, true, "rpc error: code = " +
			"Internal desc = invalid User organization"},
		{&pb.UserRequest{User: testUser9}, true, "rpc error: code = " +
			"Internal desc = invalid User last name"},
	}

	for _, c := range cases {
		s := Service{}
		response, err := s.CreateUser(context.TODO(), c.request)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Equal(t, codes.OK.String(), response.GetMessage())
		}
	}
}

func TestDeleteUser(t *testing.T) {
	// insert valid user
	insertUser := &pb.User{
		FirstName:    "Delete",
		LastName:     "User",
		Email:        "deleteUserTest@email.com",
		Password:     "12345678",
		Organization: "Delete User Test",
	}

	s := Service{}
	response, err := s.CreateUser(context.TODO(), &pb.UserRequest{User: insertUser})
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response.GetMessage())

	// generate a valid uuid to test non existent uuid in table
	uuid, err := generateUUID()
	assert.Nil(t, err)
	assert.NotNil(t, uuid)

	// exisiting uuid
	test1 := &pb.User{
		Uuid: response.GetUser().GetUuid(),
	}

	// nonexistent uuid
	test2 := &pb.User{
		Uuid: uuid,
	}

	// invalid uuid's
	test3 := &pb.User{
		Uuid: "",
	}
	test4 := &pb.User{
		Uuid: "01d1nba01gnzbrkbfrrvgrz2m",
	}

	cases := []struct {
		request  *pb.UserRequest
		isExpErr bool
		expMsg   string
	}{
		{&pb.UserRequest{User: test1}, false, codes.OK.String()},
		{&pb.UserRequest{User: test2}, true, "rpc error: code = NotFound desc = uuid does not exist in database"},
		{&pb.UserRequest{User: test3}, true, "rpc error: code = Internal desc = invalid User uuid"},
		{&pb.UserRequest{User: test4}, true, "rpc error: code = Internal desc = invalid User uuid"},
		{&pb.UserRequest{User: nil}, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
	}

	for _, c := range cases {
		s = Service{}
		response, err := s.DeleteUser(context.TODO(), c.request)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
			assert.Nil(t, response)
		} else {
			assert.Equal(t, codes.OK.String(), response.GetMessage())
			assert.Nil(t, err)
		}
	}
}

func TestGetUser(t *testing.T) {
	// insert valid user
	insertUser := &pb.User{
		FirstName:    "Get",
		LastName:     "User",
		Email:        "getUserTest@email.com",
		Password:     "12345678",
		Organization: "Get User Test",
	}

	s := Service{}
	response, err := s.CreateUser(context.TODO(), &pb.UserRequest{User: insertUser})
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response.GetMessage())

	// generate a valid uuid to test non existent uuid in table
	uuid, err := generateUUID()
	assert.Nil(t, err)
	assert.NotNil(t, uuid)

	// exisiting uuid
	test1 := &pb.User{
		Uuid: response.GetUser().GetUuid(),
	}

	// nonexistent uuid
	test2 := &pb.User{
		Uuid: uuid,
	}

	cases := []struct {
		request  *pb.UserRequest
		isExpErr bool
		expMsg   string
	}{
		{&pb.UserRequest{User: test1}, false, ""},
		{&pb.UserRequest{User: test2}, true, "rpc error: code = Internal desc = uuid does not exist in database"},
		{&pb.UserRequest{User: nil}, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
	}

	for _, c := range cases {
		s = Service{}
		response, err := s.GetUser(context.TODO(), c.request)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
			assert.Nil(t, response)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, codes.OK.String(), response.GetMessage())
		}
	}
}

func TestUpdateUser(t *testing.T) {
	// prospective email is NULL
	// is_verified stays same as last value (t)
	// password is hashed
	// modified_date set
	updateUser := &pb.User{
		FirstName:    "UPDATE",
		LastName:     "UPDATE",
		Password:     "1234567789",
		Organization: "UPDATE ORGANIZATION",
		Uuid:         "0000xsnjg0mqjhbf4qx1efd6y3",
	}

	// test prospective_email is set
	// is_verified set to false from (t)
	// modified_date set
	updateUser2 := &pb.User{
		Email: "UPDATE_USER@new.com",
		Uuid:  "0000xsnjg0mqjhbf4qx1efd6y4",
	}

	// invalid uuid
	updateUser3 := &pb.User{
		LastName: "Invalid uuid",
		Uuid:     "0000xsnjg0mqjhbf4qx",
	}

	// non-existent uuid
	updateUser4 := &pb.User{
		LastName: "uuid does not exist",
		Uuid:     "1000xsnjg0mqjhbf4qx1efd6ba",
	}

	// invalid email format
	updateUser5 := &pb.User{
		LastName: "Invalid email",
		Email:    "a",
		Uuid:     "0000xsnjg0mqjhbf4qx1efd6y4",
	}

	// invalid first name
	updateUser6 := &pb.User{
		FirstName: "@@@",
		Uuid:      "0000xsnjg0mqjhbf4qx1efd6y4",
	}

	// invalid last name
	updateUser7 := &pb.User{
		LastName: "@@@",
		Uuid:     "0000xsnjg0mqjhbf4qx1efd6y4",
	}

	cases := []struct {
		request  *pb.UserRequest
		isExpErr bool
		expMsg   string
	}{
		{&pb.UserRequest{User: updateUser}, false, ""},
		{&pb.UserRequest{User: updateUser2}, false, ""},
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{User: updateUser3}, true,
			"rpc error: code = Internal desc = invalid User uuid"},
		{&pb.UserRequest{User: updateUser4}, true,
			"rpc error: code = Internal desc = uuid does not exist in database"},
		{&pb.UserRequest{User: updateUser5}, true,
			"rpc error: code = Internal desc = invalid User email"},
		{&pb.UserRequest{User: updateUser6}, true,
			"rpc error: code = Internal desc = invalid User first name"},
		{&pb.UserRequest{User: updateUser7}, true,
			"rpc error: code = Internal desc = invalid User last name"},
		{&pb.UserRequest{User: nil}, true,
			"rpc error: code = InvalidArgument desc = nil request User"},
	}

	for _, c := range cases {
		s := Service{}
		response, err := s.UpdateUser(context.TODO(), c.request)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
			assert.Nil(t, response)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, codes.OK.String(), response.GetMessage())
		}
	}
}

func TestAuthenticateUser(t *testing.T) {
	templateDirectory = "../tmpl/"

	validPassword := "12345678"

	newUser := &pb.User{
		FirstName:    "Test",
		LastName:     "AuthenticateUser",
		Email:        "authenticate@test.com",
		Password:     validPassword,
		Organization: "hwsc",
	}

	// create user using a service (b/c cannot hard insert a hashed password)
	s := Service{}
	response, err := s.CreateUser(context.TODO(), &pb.UserRequest{User: newUser})
	assert.Nil(t, err)
	assert.Equal(t, codes.OK.String(), response.Message)

	createdUser := response.GetUser()
	assert.NotNil(t, createdUser)

	validUUID := createdUser.GetUuid()
	validEmail := createdUser.GetEmail()

	// valid user
	validUser := &pb.User{
		Uuid:     validUUID,
		Email:    validEmail,
		Password: validPassword,
	}

	// non existing uuid
	invalidUser1 := &pb.User{
		Uuid:     "0000bsnjg0mqjhbf4qx1efd6a1",
		Email:    validEmail,
		Password: validPassword,
	}

	// non existing email
	invalidUser2 := &pb.User{
		Uuid:     validUUID,
		Email:    "nonexistent@email.none",
		Password: validPassword,
	}

	// non matching password
	invalidUser3 := &pb.User{
		Uuid:     validUUID,
		Email:    validEmail,
		Password: "mismatchingpassword",
	}

	// invalid uuid form
	invalidUser4 := &pb.User{
		Uuid:     "0000xsnjg0mq",
		Email:    validEmail,
		Password: validPassword,
	}

	// invalid email form
	invalidUser5 := &pb.User{
		Uuid:     validUUID,
		Email:    "@",
		Password: validPassword,
	}

	// invalid password
	invalidUser6 := &pb.User{
		Uuid:     validUUID,
		Email:    validEmail,
		Password: "",
	}

	// missing uuid
	invalidUser7 := &pb.User{
		Email:    validEmail,
		Password: validPassword,
	}

	// missing email
	invalidUser8 := &pb.User{
		Uuid:     validUUID,
		Password: validPassword,
	}

	// missing password
	invalidUser9 := &pb.User{
		Uuid:  validUUID,
		Email: validEmail,
	}

	cases := []struct {
		request  *pb.UserRequest
		isExpErr bool
		expMsg   string
	}{
		{&pb.UserRequest{User: validUser}, false, ""},
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{User: nil}, true,
			"rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{User: invalidUser1}, true,
			"rpc error: code = Unknown desc = uuid does not exist in database"},
		{&pb.UserRequest{User: invalidUser2}, true,
			"rpc error: code = InvalidArgument desc = email does not match"},
		{&pb.UserRequest{User: invalidUser3}, true,
			"rpc error: code = Unknown desc = crypto/bcrypt: " +
				"hashedPassword is not the hash of the given password"},
		{&pb.UserRequest{User: invalidUser4}, true,
			"rpc error: code = Unknown desc = invalid User uuid"},
		{&pb.UserRequest{User: invalidUser5}, true,
			"rpc error: code = InvalidArgument desc = invalid User email"},
		{&pb.UserRequest{User: invalidUser6}, true,
			"rpc error: code = InvalidArgument desc = invalid User password"},
		{&pb.UserRequest{User: invalidUser7}, true,
			"rpc error: code = Unknown desc = invalid User uuid"},
		{&pb.UserRequest{User: invalidUser8}, true,
			"rpc error: code = InvalidArgument desc = invalid User email"},
		{&pb.UserRequest{User: invalidUser9}, true,
			"rpc error: code = InvalidArgument desc = invalid User password"},
	}

	for _, c := range cases {
		s := Service{}
		response, err := s.AuthenticateUser(context.TODO(), c.request)
		if c.isExpErr {
			assert.Nil(t, response)
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, codes.OK.String(), response.Message)
		}
	}
}
