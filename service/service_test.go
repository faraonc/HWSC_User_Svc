package service

import (
	"context"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"testing"
)

func TestGetStatus(t *testing.T) {
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
	// test disconnected mongo writer
	err := disconnectMongoClient(mongoClientWriter)
	assert.Nil(t, err)
	response, _ := s.GetStatus(context.TODO(), &pb.UserRequest{})
	assert.Equal(t, codes.OK.String(), response.GetMessage())

	// test disconnected mongo reader
	//err = disconnectMongoClient(mongoClientReader)
	//assert.Nil(t,err)
	//response, _ = s.GetStatus(context.TODO(), &pb.UserRequest{})
	//assert.Equal(t, codes.OK.String(), response.GetMessage())
}

func TestCreateUser(t *testing.T) {
	// duplicate email test
	testUser1 := &pb.User{
		Uuid: "",
		FirstName: "Santa",
		LastName: "Claus",
		Email: "hwsc.test+user1@gmail.com",
		Organization: "Test User 1",
	}

	// valid
	testUser2 := &pb.User{
		Uuid: "",
		FirstName: "James",
		LastName: "Buenafe",
		Email: "hwsc.test+user5@gmail.com",
		Organization: "Test User 2",
	}

	cases := []struct {
		request *pb.UserRequest
		isExpErr bool
		expMsg string
	} {
		{nil, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{}, true, "rpc error: code = InvalidArgument desc = nil request User"},
		{&pb.UserRequest{User: testUser1}, true, ""},
		{&pb.UserRequest{User: testUser2}, false, ""},
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
