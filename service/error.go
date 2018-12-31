package service

import (
	"errors"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"google.golang.org/grpc/codes"
)

var (
	errNilPostgresClient       = errors.New("nil Postgres Client")
	errNilRequestUser          = errors.New("nil request User")
	errEmailTaken              = errors.New("email is already taken")
	errInvalidUserFirstName    = errors.New("invalid User first name")
	errInvalidUserLastName     = errors.New("invalid User last name")
	errInvalidUserEmail        = errors.New("invalid User email")
	errInvalidPassword         = errors.New("invalid User password")
	errInvalidUserOrganization = errors.New("invalid User organization")
	errEmptyPassword           = errors.New("password is blank")

	responseServiceUnavailable = &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}
)
