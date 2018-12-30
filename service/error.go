package service

import "errors"

var (
	errNilPostgresClient       = errors.New("nil Postgres Client")
	errNilRequestUser          = errors.New("nil request User")
	errEmailTaken              = errors.New("email is already taken")
	errInvalidUserFirstName    = errors.New("invalid User first name")
	errInvalidUserLastName     = errors.New("invalid User last name")
	errInvalidUserEmail        = errors.New("invalid User email")
	errInvalidPassword         = errors.New("invalid User password")
	errInvalidUserOrganization = errors.New("invalid User organization")
)
