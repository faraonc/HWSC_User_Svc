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
	log.Println(logtag.Info, "Requesting GetStatus service")
	//TODO
	return nil, nil
}