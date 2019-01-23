package service

import (
	"errors"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"google.golang.org/grpc/codes"
)

var (
	errServiceUnavailable           = errors.New("service unavailable")
	errNilPostgresClient            = errors.New("nil Postgres Client")
	errNilRequestUser               = errors.New("nil request User")
	errEmailTaken                   = errors.New("email is already taken")
	errInvalidToken                 = errors.New("invalid token")
	errInvalidUUID                  = errors.New("invalid User uuid")
	errInvalidUserFirstName         = errors.New("invalid User first name")
	errInvalidUserLastName          = errors.New("invalid User last name")
	errInvalidUserEmail             = errors.New("invalid User email")
	errInvalidPassword              = errors.New("invalid User password")
	errInvalidUserOrganization      = errors.New("invalid User organization")
	errEmailMainTemplateNotProvided = errors.New("email main template not provided")
	errEmailNilFilePaths            = errors.New("nil email template file paths")
	errEmailRequestFieldsEmpty      = errors.New("empty or nil fields in emailRequest struct")
	errDoesNotExistUUID             = errors.New("uuid does not exist in database")
	responseServiceUnavailable      = &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
)
