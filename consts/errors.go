package consts

import (
	"errors"
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	MsgErrInsertUser            string = "unable to insert new user into db:"
	MsgErrInsertToken           string = "unable to insert token into db:"
	MsgErrGeneratingUUID        string = "generating uuid:"
	MsgErrGeneratingToken       string = "generating token:"
	MsgErrGeneratingSignedToken string = "generating signed token:"
	MsgErrEmailRequest          string = "unable to make email request object:"
	MsgErrSendEmail             string = "unable to send email:"
	MsgErrCheckUser             string = "checking user exists:"
	MsgErrDeleteUser            string = "unable to delete user:"
	MsgErrGetUserRow            string = "unable to get user row:"
	MsgErrUpdateUserRow         string = "unable to update user row:"
	MsgErrAuthenticateUser      string = "failed to authenticate user:"
	MsgErrMatchPassword         string = "failed to match password:"
	MsgErrMatchEmail            string = "email does not match"
)

var (
	ErrServiceUnavailable           = errors.New("service unavailable")
	ErrNilRequestUser               = errors.New("nil request User")
	ErrEmptyRequestUser             = errors.New("empty fields in request User")
	ErrInvalidTokenSize             = errors.New("invalid token size")
	ErrInvalidUUID                  = errors.New("invalid User uuid")
	ErrInvalidUserFirstName         = errors.New("invalid User first name")
	ErrInvalidUserLastName          = errors.New("invalid User last name")
	ErrInvalidUserEmail             = errors.New("invalid User email")
	ErrInvalidPassword              = errors.New("invalid User password")
	ErrInvalidUserOrganization      = errors.New("invalid User organization")
	ErrEmailMainTemplateNotProvided = errors.New("email main template not provided")
	ErrEmailNilFilePaths            = errors.New("nil email template file paths")
	ErrEmailRequestFieldsEmpty      = errors.New("empty or nil fields in emailRequest struct")
	ErrUUIDNotFound                 = errors.New("uuid does not exist in database")
	ResponseServiceUnavailable      = &pbsvc.UserResponse{
		Status:  &pbsvc.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
	ErrStatusServiceUnavailable = status.Error(codes.Unavailable, ErrServiceUnavailable.Error())
	ErrStatusNilRequestUser     = status.Error(codes.InvalidArgument, ErrNilRequestUser.Error())
	ErrStatusUUIDNotFound       = status.Error(codes.NotFound, ErrUUIDNotFound.Error())
	ErrStatusUUIDInvalid        = status.Error(codes.InvalidArgument, ErrInvalidUUID.Error())
)
