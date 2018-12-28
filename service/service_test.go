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
