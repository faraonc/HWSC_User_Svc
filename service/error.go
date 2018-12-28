package service

import "errors"

var (
	errNilPostgresClient = errors.New("nil Postgres Client")
)
