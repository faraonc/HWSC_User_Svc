package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	uuidLocker         sync.Mutex
	tokenLocker        sync.Mutex
	uuidMapLocker      sync.Map

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

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		return responseServiceUnavailable, nil
	}

	if err := refreshDBConnection(); err != nil {
		return responseServiceUnavailable, nil
	}

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// CreateUser creates a new user document and inserts it to user DB
func (s *Service) CreateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("CreateUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(createUserTag, errServiceUnavailable.Error())
		return nil, statusServiceUnavailable
	}

	if req == nil {
		return nil, statusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, statusNilRequestUser
	}

	// generate uuid synchronously to prevent users getting the same uuid
	var err error
	user.Uuid, err = generateUUID()
	if err != nil {
		logger.Error(createUserTag, msgErrGeneratingUUID, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// sync.Map equivalent to map[string](&sync.RWMutex{}) = each uuid string gets its own lock
	// LoadOrStore = LOAD: get the lock for uuid or if not exist,
	// 				 STORE: make uuid key and store lock type &sync.RWMutex{}
	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// insert user into DB
	if err := insertNewUser(user); err != nil {
		// remove unstored/invaid uuid from cache uuidMapLocker b/c
		// Mutex was allocated (saves resources/memory and prevent security issues)
		uuidMapLocker.Delete(user.GetUuid())
		logger.Error(createUserTag, msgErrInsertUser, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// insert token into db
	if err := insertToken(user.GetUuid()); err != nil {
		logger.Error(createUserTag, msgErrInsertToken, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// send email
	emailReq, err := newEmailRequest(nil, []string{user.GetEmail()}, conf.EmailHost.Username, subjectVerifyEmail)
	if err != nil {
		logger.Error(createUserTag, msgErrEmailRequest, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := emailReq.sendEmail(templateVerifyEmail); err != nil {
		logger.Error(createUserTag, msgErrSendEmail, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Inserted new user:", user.GetUuid())

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    &pb.User{Uuid: user.GetUuid()},
	}, nil
}

// DeleteUser deletes a user document in user DB
func (s *Service) DeleteUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("DeleteUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(deleteUserTag, errServiceUnavailable.Error())
		return nil, statusServiceUnavailable
	}

	if req == nil {
		return nil, statusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, statusNilRequestUser
	}

	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// check uuid exists
	exists, err := checkUserExists(user.GetUuid())
	if err != nil {
		logger.Error(deleteUserTag, msgErrCheckUser, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if !exists {
		logger.Error(deleteUserTag, errUUIDNotFound.Error())
		return nil, statusUUIDNotFound
	}

	// delete from db
	if err := deleteUserRow(user.GetUuid()); err != nil {
		logger.Error(deleteUserTag, msgErrDeleteUser, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Deleted user:", user.GetUuid())

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// UpdateUser updates a user document in user DB
func (s *Service) UpdateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("UpdateUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(updateUserTag, errServiceUnavailable.Error())
		return nil, statusServiceUnavailable
	}

	if req == nil {
		return nil, statusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	svcDerivedUser := req.GetUser()
	if svcDerivedUser == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, statusNilRequestUser
	}

	lock, _ := uuidMapLocker.LoadOrStore(svcDerivedUser.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// retrieve users row from database
	dbDerivedUser, err := getUserRow(svcDerivedUser.GetUuid())
	if err != nil {
		logger.Error(updateUserTag, msgErrGetUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if dbDerivedUser == nil {
		logger.Error(updateUserTag, errUUIDNotFound.Error())
		return nil, statusUUIDNotFound
	}

	// update user
	if err := updateUserRow(svcDerivedUser.GetUuid(), svcDerivedUser, dbDerivedUser); err != nil {
		logger.Error(updateUserTag, msgErrUpdateUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Updated user:", svcDerivedUser.GetUuid())

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// AuthenticateUser goes through user DB collection and tries to find matching email/password
func (s *Service) AuthenticateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logger.RequestService("AuthenticateUser")
	return &pb.UserResponse{}, nil
}

// ListUsers returns the user DB collection
func (s *Service) ListUsers(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logger.RequestService("ListUsers")
	return &pb.UserResponse{}, nil
}

// GetUser returns a user document in user DB
func (s *Service) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("GetUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(getUserTag, errServiceUnavailable.Error())
		return nil, statusServiceUnavailable
	}

	if req == nil {
		return nil, statusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, statusNilRequestUser
	}

	// read lock, b/c we are only retrieving/reading from the DB
	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).RLock()
	defer lock.(*sync.RWMutex).RUnlock()

	// retrieve users row from database
	user, err := getUserRow(user.GetUuid())
	if err != nil {
		logger.Error(getUserTag, msgErrGetUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if user == nil {
		logger.Error(getUserTag, errUUIDNotFound.Error())
		return nil, statusUUIDNotFound
	}

	logger.Info("Retrieved user:", user.GetUuid())

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    user,
	}, nil
}

// ShareDocument updates user/s documents shared_to_me field in user DB
func (s *Service) ShareDocument(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logger.RequestService("ShareDocument")
	return &pb.UserResponse{}, nil
}
