package service

import (
	"errors"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	msgErrInsertUser     string = "unable to insert new user into db:"
	msgErrInsertToken    string = "unable to insert token into db:"
	msgErrGeneratingUUID string = "generating uuid:"
	msgErrEmailRequest   string = "unable to make email request object:"
	msgErrSendEmail      string = "unable to send email:"
	msgErrCheckUser      string = "checking user exists:"
	msgErrDeleteUser     string = "unable to delete user:"
	msgErrGetUserRow     string = "unable to get user row:"
	msgErrUpdateUserRow  string = "unable to update user row:"
)

var (
	errServiceUnavailable           = errors.New("service unavailable")
	errNilPostgresClient            = errors.New("nil Postgres Client")
	errNilRequestUser               = errors.New("nil request User")
	errEmptyRequestUser             = errors.New("empty fields in request User")
	errInvalidUserFields            = errors.New("invalid field values in request User")
	errInvalidUUID                  = errors.New("invalid User uuid")
	errInvalidUserFirstName         = errors.New("invalid User first name")
	errInvalidUserLastName          = errors.New("invalid User last name")
	errInvalidUserEmail             = errors.New("invalid User email")
	errInvalidPassword              = errors.New("invalid User password")
	errInvalidUserOrganization      = errors.New("invalid User organization")
	errEmailMainTemplateNotProvided = errors.New("email main template not provided")
	errEmailNilFilePaths            = errors.New("nil email template file paths")
	errEmailRequestFieldsEmpty      = errors.New("empty or nil fields in emailRequest struct")
	errUUIDNotFound                 = errors.New("uuid does not exist in database")
	responseServiceUnavailable      = &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
	statusServiceUnavailable = status.Error(codes.Unavailable, errServiceUnavailable.Error())
	statusNilRequestUser     = status.Error(codes.InvalidArgument, errNilRequestUser.Error())
	statusUUIDNotFound       = status.Error(codes.NotFound, errUUIDNotFound.Error())
)
