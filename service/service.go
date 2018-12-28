package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"sync"
)

// Service struct type, implements the generated (pb file) UserServiceServer interface
type Service struct{}

// state of the service
type state uint32

// stateLocker synchronizes the state of the service
type stateLocker struct {
	lock                sync.RWMutex
	currentServiceState state
}

const (
	// available - service is ready and available for read/write
	available state = 0

	// unavailable - service is locked
	unavailable state = 1
)

var (
	serviceStateLocker stateLocker

	// converts the state of the service to a string
	serviceStateMap map[state]string
)

func init() {
	serviceStateLocker = stateLocker{
		currentServiceState: available,
	}

	serviceStateMap = map[state]string{
		available:   "Available",
		unavailable: "Unavailable",
	}
}

// GetStatus gets the current status of the service
// Returns status code int and status code text, and any connection errors
func (s *Service) GetStatus(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	log.RequestService("GetStatus")

	// Lock the state for reading and defer unlocks the state before function exits
	serviceStateLocker.lock.RLock()
	defer serviceStateLocker.lock.RUnlock()

	log.Info("Service state:", serviceStateMap[serviceStateLocker.currentServiceState])
	if serviceStateLocker.currentServiceState == unavailable {
		return &pb.UserResponse{
			Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
			Message: codes.Unavailable.String(),
		}, nil
	}

	if response := refreshDBConnection(); response != nil {
		return response, nil
	}

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
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
