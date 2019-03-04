package service

import (
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	pblib "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-lib/validation"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
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

	// jwtExpirationTime in hours
	jwtExpirationTime = 2
)

var (
	serviceStateLocker stateLocker
	uuidMapLocker      sync.Map
	secretLocker       sync.RWMutex

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

// GetStatus checks the current status of the service.
// On success, returns OK status and message.
func (s *Service) GetStatus(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("GetStatus")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		return consts.ResponseServiceUnavailable, nil
	}

	if err := refreshDBConnection(); err != nil {
		return consts.ResponseServiceUnavailable, nil
	}

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// CreateUser creates a new User row and inserts it to accounts table.
// On success, returns user object with password set to empty for security reasons.
func (s *Service) CreateUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    user,
	}, nil
}

// DeleteUser deletes a user row in accounts table.
// Releases mutex resource stored in uuidMapLocker by deleting the uuid.
// Method is idempotent, returns OK regardless of user not existing in accounts table and uuidMapLocker.
func (s *Service) DeleteUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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

	if err := validation.ValidateUserUUID(user.GetUuid()); err != nil {
		logger.Error(consts.DeleteUserTag, authconst.ErrInvalidUUID.Error())
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

	// release mutex resource
	uuidMapLocker.Delete(user.GetUuid())

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    &pblib.User{Uuid: user.GetUuid()},
	}, nil
}

// UpdateUser performs a partial update to a user row in accounts table.
// Method is idempotent, will perform a partial update regardless of any changes or not.
// If no changes are present, it will rewrite the selected columns with existing values.
// On success, returns user object regardless of change or not.
func (s *Service) UpdateUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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

	if err := validation.ValidateUserUUID(svcDerivedUser.GetUuid()); err != nil {
		logger.Error(consts.UpdateUserTag, authconst.ErrInvalidUUID.Error())
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
	var updatedUser *pblib.User
	updatedUser, err = updateUserRow(svcDerivedUser.GetUuid(), svcDerivedUser, dbDerivedUser)
	if err != nil {
		logger.Error(consts.UpdateUserTag, consts.MsgErrUpdateUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	logger.Info("Updated user:", updatedUser.GetUuid(),
		updatedUser.GetFirstName(), updatedUser.GetLastName())

	updatedUser.Password = ""
	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    updatedUser,
	}, nil
}

// AuthenticateUser goes through accounts table and find matching email and password.
// On success, returns the matched row as user object, setting password to empty.
func (s *Service) AuthenticateUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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
	if err := validation.ValidateUserUUID(user.GetUuid()); err != nil {
		logger.Error(consts.AuthenticateUserTag, authconst.ErrInvalidUUID.Error())
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
	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    retrievedUser,
	}, nil
}

// ListUsers returns the user DB collection
// TODO write return values after implementing
func (s *Service) ListUsers(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	//TODO
	logger.RequestService("ListUsers")
	return &pbsvc.UserResponse{}, nil
}

// GetUser looks up a user by their uuid in accounts table.
// On success, returns the matched row as user object, setting password to empty.
func (s *Service) GetUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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

	if err := validation.ValidateUserUUID(user.GetUuid()); err != nil {
		logger.Error(consts.GetUserTag, authconst.ErrInvalidUUID.Error())
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
	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    retrievedUser,
	}, nil
}

// ShareDocument updates user/s documents shared_to_me field in user DB
// TODO write return values after implementation
func (s *Service) ShareDocument(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	//TODO
	logger.RequestService("ShareDocument")
	return &pbsvc.UserResponse{}, nil
}

// GetSecret looks up active secret (marked with true boolean) from secrets table.
// If no active secrets were found, this method will generate and insert a new secret to secrets table.
// On success, returns retrieved secret if active secret was found or new secret.
func (s *Service) GetSecret(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("GetSecret")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.GetSecret, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// the chance of creating a new secret is very slim thus the usage of read lock
	secretLocker.RLock()
	defer secretLocker.RUnlock()

	// check for any active secret
	exists, err := hasActiveSecret()
	if err != nil {
		logger.Error(consts.GetSecret, consts.MsgErrLookUpActiveSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// no active key was found in DB, create and insert new secret
	if !exists {
		if err := insertNewSecret(); err != nil {
			logger.Error(consts.GetSecret, consts.MsgErrSecret, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	retrievedSecret, err := getActiveSecretRow()
	if err != nil {
		logger.Error(consts.GetSecret, consts.MsgErrGetActiveSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		Identification: &pblib.Identification{
			Secret: retrievedSecret,
		},
	}, nil
}

// GetAuthToken returns a token and secret based on the following criterias:
// If a user exists, token isn't expired, and permission matches, returns existing token and matching secret.
// If a user exists and permission does not match, returns error.
// Else a new token is generated and returned with current secret.
func (s *Service) GetAuthToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("GetAuthToken")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.GetAuthTokenTag, consts.ErrServiceUnavailable.Error())
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
		return nil, consts.ErrStatusNilRequestUser
	}

	// validate uuid, email, password
	if err := validation.ValidateUserUUID(user.GetUuid()); err != nil {
		logger.Error(consts.GetAuthTokenTag, authconst.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}
	if err := validateEmail(user.GetEmail()); err != nil {
		logger.Error(consts.GetAuthTokenTag, consts.ErrInvalidUserEmail.Error())
		return nil, status.Error(codes.InvalidArgument, consts.ErrInvalidUserEmail.Error())
	}
	if err := validatePassword(user.GetPassword()); err != nil {
		logger.Error(consts.GetAuthTokenTag, consts.ErrInvalidPassword.Error())
		return nil, status.Error(codes.InvalidArgument, consts.ErrInvalidPassword.Error())
	}

	// write lock b/c we are writing to DB
	lock, _ := uuidMapLocker.LoadOrStore(user.GetUuid(), &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// look up email and password
	retrievedUser, err := getUserRow(user.GetUuid())
	if err != nil {
		logger.Error(consts.GetAuthTokenTag, consts.MsgErrAuthenticateUser, err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	if retrievedUser.GetEmail() != user.GetEmail() {
		logger.Error(consts.GetAuthTokenTag, consts.MsgErrMatchEmail)
		return nil, status.Error(codes.InvalidArgument, consts.MsgErrMatchEmail)
	}

	if err := comparePassword(retrievedUser.GetPassword(), user.GetPassword()); err != nil {
		logger.Error(consts.GetAuthTokenTag, consts.MsgErrMatchPassword, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	var identity *pblib.Identification

	existingToken, err := getExistingToken(retrievedUser.GetUuid())
	if err == nil {
		if existingToken.permission != retrievedUser.PermissionLevel {
			logger.Error(consts.GetAuthTokenTag, consts.MsgErrPermissionMismatch)
			return nil, status.Error(codes.Unauthenticated, consts.MsgErrPermissionMismatch)
		}
		identity = &pblib.Identification{
			Token:  existingToken.token,
			Secret: existingToken.secret,
		}
	} else {
		permissionLevel := auth.PermissionEnumMap[retrievedUser.GetPermissionLevel()]

		// build token header, body, secret
		header := &auth.Header{
			Alg:      auth.AlgorithmMap[permissionLevel],
			TokenTyp: auth.Jwt,
		}
		body := &auth.Body{
			UUID:                retrievedUser.GetUuid(),
			Permission:          permissionLevel,
			ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(jwtExpirationTime)).Unix(),
		}

		if err := setCurrentSecretOnce(); err != nil {
			logger.Error(consts.GetAuthTokenTag, consts.MsgErrGetActiveSecret, err.Error())
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		newToken, err := auth.NewToken(header, body, currSecret)
		if err != nil {
			logger.Error(consts.GetAuthTokenTag, consts.MsgErrGeneratingToken, err.Error())
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// insert token into db for auditing
		if err := insertJWToken(newToken, header, body, currSecret); err != nil {
			logger.Error(consts.GetAuthTokenTag, consts.MsgErrInsertingJWToken, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}

		identity = &pblib.Identification{
			Token:  newToken,
			Secret: currSecret,
		}
	}

	return &pbsvc.UserResponse{
		Status:         &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message:        codes.OK.String(),
		Identification: identity,
	}, nil
}

// VerifyAuthToken checks if received token and retrieved secret is valid.
// Token is first verified against tokens table, and if token is found, secret is retrieved.
// On success, returns identity object with token and paired secret.
func (s *Service) VerifyAuthToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("Verify Auth Token")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.VerifyToken, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get identification object
	identity := req.GetIdentification()
	if identity == nil {
		return nil, status.Error(codes.InvalidArgument, consts.ErrNilRequestIdentification.Error())
	}

	// verify token against database
	retrievedIdentity, err := pairTokenWithSecret(identity.GetToken())
	if err != nil {
		logger.Error(consts.VerifyToken, consts.MsgErrValidatingToken, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// create authority to validate Identity containing token and retrieved secret
	authority := auth.NewAuthority(auth.Jwt, auth.User)
	if err := authority.Authorize(retrievedIdentity); err != nil {
		logger.Error(consts.VerifyToken, consts.MsgErrValidatingIdentity, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// invalidate authority and identity's secret for security reasons
	authority.Invalidate()

	return &pbsvc.UserResponse{
		Status:         &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message:        codes.OK.String(),
		Identification: retrievedIdentity,
	}, nil
}

// MakeNewSecret generates and inserts a new secret into DB and
// thereby update the currSecret with the newly generated secret.
// On success, returns message and status marked with OK.
func (s *Service) MakeNewSecret(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("MakeNewSecret")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.MakeNewSecret, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	secretLocker.Lock()
	defer secretLocker.Unlock()

	// insert new secret
	if err := insertNewSecret(); err != nil {
		logger.Error(consts.MakeNewSecret, consts.MsgErrSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// retrieve the newly updated active secret and set it as the currSecret
	retrievedSecret, err := getActiveSecretRow()
	if err != nil {
		logger.Error(consts.MakeNewSecret, consts.MsgErrGetActiveSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}
	currSecret = retrievedSecret

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// VerifyEmailToken checks if received token is found in the email_tokens table.
// If found and token is NOT expired, returns OK.
// If found, but token IS expired, the token row with expired token will be deleted,
// service will generate a new email token and insert into email_tokens table,
// and return ERROR with token expired message.
// If token is not found, return ERROR with token does not exist message.
func (s *Service) VerifyEmailToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	// TODO
	return nil, nil
}
