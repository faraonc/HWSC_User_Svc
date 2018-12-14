package service

import (
	"flag"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"golang.org/x/net/context"
)

var (
	// allows for command line changing of deadlines, default deadline: 20,000 ms = 20 sec
	deadlineMsDB = flag.Int("deadline_ms", 20*1000, "Default deadline in milliseconds")
)

// Service struct type, implements the generated (pb file) UserServiceServer interface
type Service struct{}

func init() {
	// executes command line parsing of deadlineMs, defaults to 20,000 ms
	// flag.Parse();
}

// GetStatus gets the current status of the service
func (s *Service) GetStatus(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("GetStatus")
	return &pb.UserResponse{}, nil
}

// CreateUser creates a new user document and inserts it to user DB
func (s *Service) CreateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	log.RequestService("CreateUser")
	return &pb.UserResponse{}, nil
}

// DeleteUser deletes a user document in user DB
func (s *Service) DeleteUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("DeleteUser")
	return &pb.UserResponse{}, nil
}

// UpdateUser updates a user document in user DB
func (s *Service) UpdateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("UpdateUser")
	return &pb.UserResponse{}, nil
}

// AuthenticateUser goes through user DB collection and tries to find matching email/password
func (s *Service) AuthenticateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("AuthenticateUser")
	return &pb.UserResponse{}, nil
}

// ListUsers returns the user DB collection
func (s *Service) ListUsers(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("ListUsers")
	return &pb.UserResponse{}, nil
}

// GetUser returns a user document in user DB
func (s *Service) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("GetUser")
	return &pb.UserResponse{}, nil
}

// ShareDocument updates user/s documents shared_to_me field in user DB
func (s *Service) ShareDocument(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	log.RequestService("ShareDocument")
	return &pb.UserResponse{}, nil
}
