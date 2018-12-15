package service

import "errors"

var (
	errNilMongoClient = errors.New("nil Mongo Client")
)
