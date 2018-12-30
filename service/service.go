package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/hwsc-org/hwsc-logger/logger"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
	"time"
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
	logger.RequestService("GetStatus")

	// Lock the state for reading and defer unlocks the state before function exits
	serviceStateLocker.lock.RLock()
	defer serviceStateLocker.lock.RUnlock()

	logger.Info("Service state:", serviceStateMap[serviceStateLocker.currentServiceState])
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
	logger.RequestService("CreateUser")

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, status.Error(codes.InvalidArgument, errNilRequestUser.Error())
	}

	// validate fields in user object
	if str, err := validateUser(user); err != nil {
		logger.Error(str, ":", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// generate uuid
	id, err := generateUUID()
	if err != nil {
		logger.Error("CreateUser generateUUID:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}
	user.Uuid = id

	// hash password using bcrypt
	hashedPassword, err := hashPassword(user.GetPassword())
	if err != nil {
		logger.Error("CreateUser hashPassword:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}
	user.Password = hashedPassword
	user.IsVerified = false

	// insert into DB
	command := `
				INSERT INTO user_account(
					uuid, first_name, last_name, email, password, organization, created_date, is_verified
				) VALUES($1, $2, $3, $4, $5, $6, $7, $8)
				`
	_, err = postgresDB.Exec(command, user.GetUuid(), user.GetFirstName(), user.GetLastName(),
		user.GetEmail(), user.GetPassword(), user.GetOrganization(), time.Now().UTC(), user.GetIsVerified())

	if err != nil {
		logger.Error("CreateUser Exec INSERT:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	logger.Info("Success inserting new user:", user.GetFirstName(), user.GetLastName(), user.GetUuid())

	// NOTE: I shouldn't be sending back user object, b/c user has to verify his account first
	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

//// DeleteUser deletes a user document in user DB
//func (s *Service) DeleteUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("DeleteUser")
//	return &pb.UserResponse{}, nil
//}
//
//// UpdateUser updates a user document in user DB
//func (s *Service) UpdateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("UpdateUser")
//	return &pb.UserResponse{}, nil
//}
//
//// AuthenticateUser goes through user DB collection and tries to find matching email/password
//func (s *Service) AuthenticateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("AuthenticateUser")
//	return &pb.UserResponse{}, nil
//}
//
//// ListUsers returns the user DB collection
//func (s *Service) ListUsers(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("ListUsers")
//	return &pb.UserResponse{}, nil
//}
//
//// GetUser returns a user document in user DB
//func (s *Service) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("GetUser")
//	return &pb.UserResponse{}, nil
//}
//
//// ShareDocument updates user/s documents shared_to_me field in user DB
//func (s *Service) ShareDocument(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	logger.RequestService("ShareDocument")
//	return &pb.UserResponse{}, nil
//}
