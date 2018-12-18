package service

import "errors"

var (
	errNilMongoClient = errors.New("nil Mongo Client")
	errNilRequestUser = errors.New("nil request User")
	errEmailTaken = errors.New("email is already taken")
)
