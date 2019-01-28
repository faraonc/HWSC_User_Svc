package consts

import (
	"errors"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	MsgErrInsertUser     string = "unable to insert new user into db:"
	MsgErrInsertToken    string = "unable to insert token into db:"
	MsgErrGeneratingUUID string = "generating uuid:"
	MsgErrEmailRequest   string = "unable to make email request object:"
	MsgErrSendEmail      string = "unable to send email:"
	MsgErrCheckUser      string = "checking user exists:"
	MsgErrDeleteUser     string = "unable to delete user:"
	MsgErrGetUserRow     string = "unable to get user row:"
	MsgErrUpdateUserRow  string = "unable to update user row:"
)

var (
	ErrServiceUnavailable           = errors.New("service unavailable")
	ErrNilPostgresClient            = errors.New("nil Postgres Client")
	ErrNilRequestUser               = errors.New("nil request User")
	ErrEmptyRequestUser             = errors.New("empty fields in request User")
	ErrInvalidUserFields            = errors.New("invalid field values in request User")
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
	ResponseServiceUnavailable      = &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
	StatusServiceUnavailable = status.Error(codes.Unavailable, ErrServiceUnavailable.Error())
	StatusNilRequestUser     = status.Error(codes.InvalidArgument, ErrNilRequestUser.Error())
	StatusUUIDNotFound       = status.Error(codes.NotFound, ErrUUIDNotFound.Error())
)
