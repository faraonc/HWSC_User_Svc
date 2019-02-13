package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
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
	serviceStateMap = map[state]string{
		available:   "Available",
		unavailable: "Unavailable",
	}
)

func init() {
	serviceStateLocker = stateLocker{
		currentServiceState: available,
	}
}

// GetStatus gets the current status of the service
// Returns status code int and status code text, and any connection errors
func (s *Service) GetStatus(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("GetStatus")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		return consts.ResponseServiceUnavailable, nil
	}

	if err := refreshDBConnection(); err != nil {
		return consts.ResponseServiceUnavailable, nil
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
		logger.Error(consts.CreateUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	// generate uuid synchronously to prevent users getting the same uuid
	var err error
	user.Uuid, err = generateUUID()
	if err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrGeneratingUUID, err.Error())
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
		logger.Error(consts.CreateUserTag, consts.MsgErrInsertUser, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// insert token into db
	if err := insertEmailToken(user.GetUuid()); err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrInsertToken, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// send email
	emailReq, err := newEmailRequest(nil, []string{user.GetEmail()}, conf.EmailHost.Username, subjectVerifyEmail)
	if err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrEmailRequest, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := emailReq.sendEmail(templateVerifyEmail); err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrSendEmail, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Inserted new user:", user.GetUuid(), user.GetFirstName(), user.GetLastName())

	user.Password = ""
	user.IsVerified = false

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    user,
	}, nil
}

// DeleteUser deletes a user document in user DB
func (s *Service) DeleteUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("DeleteUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.DeleteUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := validateUUID(user.GetUuid()); err != nil {
		logger.Error(consts.DeleteUserTag, consts.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}

	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// delete from db
	if err := deleteUserRow(user.GetUuid()); err != nil {
		logger.Error(consts.DeleteUserTag, consts.MsgErrDeleteUser, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Deleted user:", user.GetUuid(), user.GetFirstName(), user.GetLastName())

	// release mutex resource
	uuidMapLocker.Delete(user.GetUuid())

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    &pb.User{Uuid: user.GetUuid()},
	}, nil
}

// UpdateUser updates a user document in user DB
func (s *Service) UpdateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("UpdateUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.UpdateUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	svcDerivedUser := req.GetUser()
	if svcDerivedUser == nil {
		logger.Error(consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := validateUUID(svcDerivedUser.GetUuid()); err != nil {
		logger.Error(consts.UpdateUserTag, consts.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}

	lock, _ := uuidMapLocker.LoadOrStore(svcDerivedUser.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// retrieve users row from database
	dbDerivedUser, err := getUserRow(svcDerivedUser.GetUuid())
	if err != nil {
		logger.Error(consts.UpdateUserTag, consts.MsgErrGetUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if dbDerivedUser == nil {
		logger.Error(consts.UpdateUserTag, consts.ErrUUIDNotFound.Error())
		return nil, consts.ErrStatusUUIDNotFound
	}

	// update user
	var updatedUser *pb.User
	updatedUser, err = updateUserRow(svcDerivedUser.GetUuid(), svcDerivedUser, dbDerivedUser)
	if err != nil {
		logger.Error(consts.UpdateUserTag, consts.MsgErrUpdateUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Updated user:", updatedUser.GetUuid(),
		updatedUser.GetFirstName(), updatedUser.GetLastName())

	updatedUser.Password = ""
	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    updatedUser,
	}, nil
}

// AuthenticateUser goes through user DB collection and tries to find matching email/password
func (s *Service) AuthenticateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("AuthenticateUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.AuthenticateUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	user := req.GetUser()
	if user == nil {
		logger.Error(consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	// validate uuid, email, password
	if err := validateUUID(user.GetUuid()); err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}
	if err := validateEmail(user.GetEmail()); err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrInvalidUserEmail.Error())
		return nil, status.Error(codes.InvalidArgument, consts.ErrInvalidUserEmail.Error())
	}
	if err := validatePassword(user.GetPassword()); err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrInvalidPassword.Error())
		return nil, status.Error(codes.InvalidArgument, consts.ErrInvalidPassword.Error())
	}

	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).RLock()
	defer lock.(*sync.RWMutex).RUnlock()

	// look up email and password
	retrievedUser, err := getUserRow(user.GetUuid())
	if err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.MsgErrAuthenticateUser, err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	if retrievedUser.GetEmail() != user.GetEmail() {
		logger.Error(consts.AuthenticateUserTag, consts.MsgErrMatchEmail)
		return nil, status.Error(codes.InvalidArgument, consts.MsgErrMatchEmail)
	}

	if err := comparePassword(retrievedUser.GetPassword(), user.GetPassword()); err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.MsgErrMatchPassword, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	logger.Info("Authenticated user:", retrievedUser.GetUuid(),
		retrievedUser.GetFirstName(), retrievedUser.GetLastName())

	retrievedUser.Password = ""
	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    retrievedUser,
	}, nil
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
		logger.Error(consts.GetUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get User Object
	user := req.GetUser()
	if user == nil {
		logger.Error(consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := validateUUID(user.GetUuid()); err != nil {
		logger.Error(consts.GetUserTag, consts.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}

	// read lock, b/c we are only retrieving/reading from the DB
	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).RLock()
	defer lock.(*sync.RWMutex).RUnlock()

	// retrieve users row from database
	retrievedUser, err := getUserRow(user.GetUuid())
	if err != nil {
		logger.Error(consts.GetUserTag, consts.MsgErrGetUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	if retrievedUser == nil {
		logger.Error(consts.GetUserTag, consts.ErrUUIDNotFound.Error())
		return nil, consts.ErrStatusUUIDNotFound
	}

	logger.Info("Retrieved user:", user.GetUuid(), user.GetFirstName(), user.GetLastName())

	retrievedUser.Password = ""
	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    retrievedUser,
	}, nil
}

// ShareDocument updates user/s documents shared_to_me field in user DB
func (s *Service) ShareDocument(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logger.RequestService("ShareDocument")
	return &pb.UserResponse{}, nil
}

// GetSecret retrieves and returns the recent/active secret from the DB
func (s *Service) GetSecret(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	logger.RequestService("Get Secret")
	return &pb.UserResponse{}, nil
}

// GetToken retrieves and returns user's token stored in DB
func (s *Service) GetToken(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	logger.RequestService("Get Token")
	return &pb.UserResponse{}, nil
}

// VerifyToken checks if received token from Chrome is valid
func (s *Service) VerifyToken(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	logger.RequestService("Verify Token")
	return &pb.UserResponse{}, nil
}

// NewSecret generates and inserts a new secret into DB
func (s *Service) NewSecret(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	logger.RequestService("New Secret")
	return &pb.UserResponse{}, nil
}
