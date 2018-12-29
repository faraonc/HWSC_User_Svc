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
	postgresDB = nil
	response = refreshDBConnection()
	assert.Nil(t, response)
}

func TestCreateUser(t *testing.T) {
	// valid
	testUser1 := &pb.User{
		Uuid: "",
		FirstName: "Stella Lilly",
		LastName: "Kim",
		Email: "stella@test.com",
		Organization: "Test User 1",
	}

	// valid
	testUser2 := &pb.User{
		Uuid: "",
		FirstName: "Ray",
		LastName: "Bradbury",
		Email: "ray@test.com",
		Organization: "Test User 2",
	}

	// fail: duplicate email test
	testUser3 := &pb.User{
		Uuid: "",
		FirstName: "Duplicate Email",
		LastName: "Test",
		Email: "ray@test.com",
		Organization: "Test User 3",
	}

	cases := []struct {
		request *pb.UserRequest
		isExpErr bool
		expMsg string
	} {
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{}, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{User: testUser1}, false, ""},
		{&pb.UserRequest{User: testUser2}, false, ""},
		{&pb.UserRequest{User: testUser3}, true, "rpc error: code = Unknown desc = pq: " +
			"duplicate key value violates unique constraint \"user_account_email_key\""},
	}

	for _, c := range cases {
		s := Service{}
		response, err:= s.CreateUser(context.TODO(), c.request)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Equal(t, codes.OK.String(), response.GetMessage())
		}
	}
}