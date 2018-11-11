package service

import (
	pb "github.com/faraonc/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"golang.org/x/net/context"
)

// This Service struct type, implements the generated (pb file) UserServiceServer interface
type Service struct{}

func (s *Service) GetStatus (ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// TODO

	return nil, nil
}