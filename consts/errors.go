package consts

import (
	"errors"
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	MsgErrInsertUser                string = "unable to insert new user into db:"
	MsgErrInsertToken               string = "unable to insert token into db:"
	MsgErrGeneratingUUID            string = "generating uuid:"
	MsgErrGeneratingToken           string = "generating token:"
	MsgErrEmailRequest              string = "unable to make email request object:"
	MsgErrSendEmail                 string = "unable to send email:"
	MsgErrDeleteUser                string = "unable to delete user:"
	MsgErrGetUserRow                string = "unable to get user row:"
	MsgErrUpdateUserRow             string = "unable to update user row:"
	MsgErrAuthenticateUser          string = "failed to authenticate user:"
	MsgErrMatchPassword             string = "failed to match password:"
	MsgErrMatchEmail                string = "email does not match"
	MsgErrSecret                    string = "failed to insert new secret into db:"
	MsgErrGetActiveSecret           string = "failed to get active secret row from db:"
	MsgErrLookUpActiveSecret        string = "failed to look up active secret from db"
	MsgErrInsertingJWToken          string = "failed to insert jwt into db:"
	MsgErrGetExistingToken          string = "error retrieving existing token:"
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
	ErrNoExistingTokenFound         = errors.New("no existing token were found for user")
	ErrNoActiveSecretKeyFound       = errors.New("no active secret key found in database")
	ErrMismatchingToken             = errors.New("tokens do not match")
	ErrInvalidRowCount              = errors.New("query resulted more than one count")
	ErrInvalidAddTime               = errors.New("add time is zero")
	ResponseServiceUnavailable      = &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
	ErrStatusServiceUnavailable = status.Error(codes.Unavailable, ErrServiceUnavailable.Error())
	ErrStatusNilRequestUser     = status.Error(codes.InvalidArgument, ErrNilRequestUser.Error())
	ErrStatusUUIDNotFound       = status.Error(codes.NotFound, ErrUUIDNotFound.Error())
	ErrStatusUUIDInvalid        = status.Error(codes.InvalidArgument, authconst.ErrInvalidUUID.Error())
)
