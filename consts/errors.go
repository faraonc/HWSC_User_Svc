package consts

import (
	"errors"
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	MsgErrInsertUser                string = "failed to insert new user into db:"
	MsgErrInsertEmailToken          string = "failed to insert email token into db:"
	MsgErrInsertAuthToken           string = "failed to insert auth token into db:"
	MsgErrGeneratingUUID            string = "error in generating uuid:"
	MsgErrGeneratingEmailToken      string = "error in generating email token:"
	MsgErrGeneratingAuthToken       string = "error in generating auth token:"
	MsgErrEmailRequest              string = "failed to make email request object:"
	MsgErrSendEmail                 string = "failed to send email:"
	MsgErrDeleteUser                string = "failed to delete user:"
	MsgErrGetUserRow                string = "failed to get user row:"
	MsgErrUpdateUserRow             string = "failed to update user row:"
	MsgErrAuthenticateUser          string = "failed to authenticate user:"
	MsgErrMatchPassword             string = "failed to match password:"
	MsgErrMatchEmail                string = "email does not match"
	MsgErrSecret                    string = "failed to insert new secret into db:"
	MsgErrGetActiveSecret           string = "failed to get active secret row from db:"
	MsgErrLookUpActiveSecret        string = "failed to look up active secret from db"
	MsgErrPermissionMismatch        string = "permission level does not match"
	MsgErrValidatingIdentity        string = "failed to validate identity:"
	MsgErrValidatingToken           string = "failed to match token with db:"
	MsgErrGeneratingEmailVerifyLink string = "failed to generate email verfication link:"
)

var (
	ErrServiceUnavailable           = errors.New("service unavailable")
	ErrNilRequestUser               = errors.New("nil request User")
	ErrNilRequestIdentification     = errors.New("nil request identification")
	ErrEmptyRequestUser             = errors.New("empty fields in request User")
	ErrInvalidTimeStamp             = errors.New("zero timestamp")
	ErrInvalidNumberOfDays          = errors.New("invalid number of days to add to expiration timestamp")
	ErrInvalidTokenSize             = errors.New("invalid token size")
	ErrInvalidUserFirstName         = errors.New("invalid User first name")
	ErrInvalidUserLastName          = errors.New("invalid User last name")
	ErrInvalidUserEmail             = errors.New("invalid User email")
	ErrInvalidPassword              = errors.New("invalid User password")
	ErrInvalidUserOrganization      = errors.New("invalid User organization")
	ErrEmailMainTemplateNotProvided = errors.New("email main template not provided")
	ErrEmailNilFilePaths            = errors.New("nil email template file paths")
	ErrEmailRequestFieldsEmpty      = errors.New("empty or nil fields in emailRequest struct")
	ErrUUIDNotFound                 = errors.New("uuid does not exist in database")
	ErrNoRowsFound                  = errors.New("no query row found in database")
	ErrNoAuthTokenFound             = errors.New("no auth token were found under given uuid")
	ErrNoMatchingAuthTokenFound     = errors.New("no matching auth token were found given token")
	ErrNoMatchingEmailTokenFound    = errors.New("no matching email token were found with given token")
	ErrNoActiveSecretKeyFound       = errors.New("no active secret key found in database")
	ErrMismatchingToken             = errors.New("tokens do not match")
	ErrMismatchingEmailToken        = errors.New("email tokens do not match")
	ErrInvalidAddTime               = errors.New("add time is zero")
	ErrEmailExists                  = errors.New("email already exists")
	ResponseServiceUnavailable      = &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
	ErrStatusServiceUnavailable = status.Error(codes.Unavailable, ErrServiceUnavailable.Error())
	ErrStatusNilRequestUser     = status.Error(codes.InvalidArgument, ErrNilRequestUser.Error())
	ErrStatusUUIDNotFound       = status.Error(codes.NotFound, ErrUUIDNotFound.Error())
	ErrStatusUUIDInvalid        = status.Error(codes.InvalidArgument, authconst.ErrInvalidUUID.Error())
)
