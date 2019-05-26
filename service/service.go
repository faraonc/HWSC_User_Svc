package service

import (
	"fmt"
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/protobuf/hwsc-user-svc/user"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
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

	// authTokenExpirationTime in hours
	authTokenExpirationTime = 2
)

var (
	serviceStateLocker stateLocker
	uuidMapLocker      sync.Map
	authSecretLocker   sync.RWMutex
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
// After row insertion, sends verification link to users email.
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

	logger.Info("Inserted new user:", user.GetUuid(), user.GetFirstName(), user.GetLastName())

	user.Password = ""
	user.IsVerified = false
	user.PermissionLevel = auth.PermissionStringMap[auth.NoPermission]

	userCreatedResponse := &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User:    user,
	}

	// from here on: do not return an error because we can always regenerate tokens and resend verification emails

	// create identification for email token
	emailID, err := generateEmailToken(user.GetUuid(), user.PermissionLevel)
	if err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrGeneratingEmailToken, err.Error())
		return userCreatedResponse, nil
	}

	// insert token into db, if nondb error returns, token will simply expire, so no need to remove
	if err := insertEmailToken(user.GetUuid(), emailID.GetToken(), emailID.GetSecret()); err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrInsertEmailToken, err.Error())
		return userCreatedResponse, nil
	}

	// generate verification link for emails
	verificationLink, err := generateEmailVerifyLink(emailID.GetToken())
	if err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrGeneratingEmailVerifyLink, err.Error())
		return userCreatedResponse, nil
	}

	// send email
	emailData := make(map[string]string)
	if verificationLink == "" {
		return userCreatedResponse, nil
	}
	emailData[verificationLinkKey] = verificationLink

	emailReq, err := newEmailRequest(emailData, []string{user.GetEmail()}, conf.EmailHost.Username, subjectVerifyEmail)
	if err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrEmailRequest, err.Error())
		return userCreatedResponse, nil
	}

	if err := emailReq.sendEmail(templateVerifyEmail); err != nil {
		logger.Error(consts.CreateUserTag, consts.MsgErrSendEmail, err.Error())
	}

	return &pbsvc.UserResponse{
		Status:         &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message:        codes.OK.String(),
		Identification: &pblib.Identification{Token: emailID.GetToken()},
		User:           user,
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
// On success, returns the identification, and matched row as user object with password set to empty string.
func (s *Service) AuthenticateUser(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("AuthenticateUser")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.AuthenticateUserTag, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrNilRequest.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	user := req.GetUser()
	if user == nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrNilRequestUser.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	if err := refreshDBConnection(); err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.ErrDBConnectionError.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// email, password
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

	// match email and password
	matchedUser, err := matchEmailAndPassword(user.GetEmail(), user.GetPassword())
	if err != nil {
		logger.Error(consts.AuthenticateUserTag, consts.MsgErrMatchEmailPassword, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	identification, err := getAuthIdentification(matchedUser)
	if err != nil {
		logger.Error(consts.AuthenticateUserTag, err.Error())
		return nil, err
	}

	logger.Info("Authenticated user:", matchedUser.GetUuid(),
		matchedUser.GetFirstName(), matchedUser.GetLastName())

	matchedUser.Password = ""
	return &pbsvc.UserResponse{
		Status:         &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message:        codes.OK.String(),
		User:           matchedUser,
		Identification: identification,
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

// GetAuthSecret looks up active secret (marked with true boolean) from secrets table.
// If no active secrets were found, this method will generate and insert a new secret to secrets table.
// On success, returns retrieved secret if active secret was found or new secret.
func (s *Service) GetAuthSecret(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("GetAuthSecret")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.GetAuthSecret, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// the chance of creating a new secret is very slim thus the usage of read lock
	// b/c an admin or a job runner will be responsible for creating new secrets
	authSecretLocker.RLock()
	defer authSecretLocker.RUnlock()

	// check for any active secret
	exists, err := hasActiveAuthSecret()
	if err != nil {
		logger.Error(consts.GetAuthSecret, consts.MsgErrLookUpActiveSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// no active key was found in DB, create and insert new secret
	if !exists {
		if err := insertNewAuthSecret(); err != nil {
			logger.Error(consts.GetAuthSecret, consts.MsgErrSecret, err.Error())
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	retrievedSecret, err := getActiveSecretRow()
	if err != nil {
		logger.Error(consts.GetAuthSecret, consts.MsgErrGetActiveSecret, err.Error())
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

// GetNewAuthToken returns a token and secret based on the following criterias:
// TODO wrong doc and implmentation
// If a user exists, token isn't expired, and permission matches, returns existing token and matching secret.
// If a user exists and permission does not match, returns error.
// Else a new token is generated and returned with current secret.
func (s *Service) GetNewAuthToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
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
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if retrievedUser.GetEmail() != user.GetEmail() {
		logger.Error(consts.GetAuthTokenTag, consts.MsgErrMatchEmail)
		return nil, status.Error(codes.InvalidArgument, consts.MsgErrMatchEmail)
	}

	if err := comparePassword(retrievedUser.GetPassword(), user.GetPassword()); err != nil {
		logger.Error(consts.GetAuthTokenTag, consts.MsgErrMatchPassword, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	identification, err := getAuthIdentification(retrievedUser)
	if err != nil {
		logger.Error(consts.GetAuthTokenTag, err.Error())
		return nil, err
	}

	return &pbsvc.UserResponse{
		Status:         &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message:        codes.OK.String(),
		Identification: identification,
	}, nil
}

// VerifyAuthToken checks if received token and retrieved secret is valid.
// Token is first verified against tokens table, and if token is found, secret is retrieved.
// On success, returns identity object with token and paired secret.
func (s *Service) VerifyAuthToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("Verify Auth Token")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.VerifyAuthToken, consts.ErrServiceUnavailable.Error())
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
		logger.Error(consts.VerifyAuthToken, consts.MsgErrValidatingToken, err.Error())
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// create authority to validate Identity containing token and retrieved secret
	authority := auth.NewAuthority(auth.Jwt, auth.User)
	if err := authority.Authorize(retrievedIdentity); err != nil {
		logger.Error(consts.VerifyAuthToken, consts.MsgErrValidatingIdentity, err.Error())
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

// MakeNewAuthSecret generates and inserts a new secret into DB and
// thereby update the currAuthSecret with the newly generated secret.
// On success, returns message and status marked with OK.
func (s *Service) MakeNewAuthSecret(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("MakeNewAuthSecret")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.MakeNewAuthSecret, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if err := refreshDBConnection(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	authSecretLocker.Lock()
	defer authSecretLocker.Unlock()

	// insert new secret
	if err := insertNewAuthSecret(); err != nil {
		logger.Error(consts.MakeNewAuthSecret, consts.MsgErrSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// retrieve the newly updated active secret and set it as the currAuthSecret
	retrievedSecret, err := getActiveSecretRow()
	if err != nil {
		logger.Error(consts.MakeNewAuthSecret, consts.MsgErrGetActiveSecret, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}
	currAuthSecret = retrievedSecret

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// VerifyEmailToken checks if received token is found in the email_tokens table.
// If found and token is NOT expired, deletes token row and returns OK.
// If found, but token IS expired, it will return a expired token error.
// Additionally for expired tokens, if user is new, it will delete token AND user row, else just deletes the token row.
// If token is not found, return error with token does not exist message.
func (s *Service) VerifyEmailToken(ctx context.Context, req *pbsvc.UserRequest) (*pbsvc.UserResponse, error) {
	logger.RequestService("VerifyEmailToken")

	if ok := serviceStateLocker.isStateAvailable(); !ok {
		logger.Error(consts.VerifyEmailToken, consts.ErrServiceUnavailable.Error())
		return nil, consts.ErrStatusServiceUnavailable
	}

	if req == nil {
		logger.Error(consts.VerifyEmailToken, consts.ErrNilRequest.Error())
		return nil, consts.ErrStatusNilRequestUser
	}

	if req.GetIdentification() == nil {
		logger.Error(consts.VerifyEmailToken, consts.ErrNilRequestIdentification.Error())
		return nil, status.Error(codes.InvalidArgument, consts.ErrNilRequestIdentification.Error())
	}

	emailToken := req.GetIdentification().GetToken()
	if emailToken == "" {
		logger.Error(consts.VerifyEmailToken, authconst.ErrEmptyToken.Error())
		return nil, status.Error(codes.InvalidArgument, authconst.ErrEmptyToken.Error())
	}

	if err := refreshDBConnection(); err != nil {
		logger.Error(consts.VerifyEmailToken, consts.ErrDBConnectionError.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	uuid := auth.ExtractUUID(emailToken)
	if uuid == "" {
		logger.Error(consts.VerifyEmailToken, authconst.ErrInvalidUUID.Error())
		return nil, consts.ErrStatusUUIDInvalid
	}

	lock, _ := uuidMapLocker.LoadOrStore(uuid, &sync.RWMutex{})
	lock.(*sync.RWMutex).Lock()
	defer lock.(*sync.RWMutex).Unlock()

	// find matching email token row
	retrievedToken, err := getEmailTokenRow(emailToken)
	if err != nil {
		logger.Error(consts.VerifyEmailToken, consts.MsgErrRetrieveEmailTokenRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// delete token row
	if err := deleteEmailTokenRow(retrievedToken.uuid); err != nil {
		logger.Error(consts.VerifyEmailToken, consts.MsgErrDeletingEmailToken)
		return nil, status.Error(codes.Internal, err.Error())
	}

	// look up user to determine permission level
	retrievedUser, err := getUserRow(retrievedToken.uuid)
	if err != nil {
		logger.Error(consts.VerifyEmailToken, consts.MsgErrGetUserRow, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	// if token is expired
	if time.Now().Unix() >= retrievedToken.expirationTimestamp || retrievedToken.expirationTimestamp <= 0 {
		// delete stale new user
		if (retrievedUser.GetProspectiveEmail() == "" && retrievedUser.GetIsVerified() == false) &&
			retrievedUser.GetPermissionLevel() == auth.PermissionStringMap[auth.NoPermission] {
			if err := deleteUserRow(retrievedToken.uuid); err != nil {
				logger.Error(consts.VerifyEmailToken, consts.MsgErrDeleteUser, " && ", consts.ErrExpiredEmailToken.Error())
				return nil, status.Error(codes.Internal, fmt.Sprintf("%s && %s", err.Error(), consts.ErrExpiredEmailToken.Error()))
			}
		}

		logger.Error(consts.VerifyEmailToken, consts.ErrExpiredEmailToken.Error())
		return nil, status.Error(codes.DeadlineExceeded, consts.ErrExpiredEmailToken.Error())
	}

	// update user's permission level
	err = updatePermissionLevel(retrievedUser.GetUuid(), auth.PermissionStringMap[auth.User])
	if err != nil {
		logger.Error(consts.VerifyEmailToken, consts.MsgErrUpdatePermLevel, err.Error())
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}
