package service

import (
	pb "github.com/faraonc/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/faraonc/hwsc-user-svc/logtag"
	"golang.org/x/net/context"
	"log"
)

// This Service struct type, implements the generated (pb file) UserServiceServer interface
type Service struct{}

func (s *Service) GetStatus (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("GetStatus")
	return nil, nil
}

func (s *Service) CreateUser (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO
	logRequestService("CreateUser")
	return nil, nil
}

func (s *Service) DeleteUser (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("DeleteUser")
	return nil, nil
}

func (s *Service) UpdateUser (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("UpdateUser")
	return nil, nil
}

func (s *Service) AuthenticateUser (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("AuthenticateUser")
	return nil, nil
}

func (s *Service) ListUsers (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("ListUsers")
	return nil, nil
}

func (s *Service) GetUser (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("GetUser")
	return nil, nil
}

func (s *Service) ShareDocument (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	//TODO
	logRequestService("ShareDocument")
	return nil, nil
}

func logRequestService (svc string) {
	log.Println(logtag.Info, "Requesting", svc, "service")
}