package main

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	svc "github.com/hwsc-org/hwsc-user-svc/service"
	"google.golang.org/grpc"
	"net"
)

func main() {
	log.Info(consts.UserServiceTag, "hwsc-user-svc initiating...")

	// make TCP listener, listen for incoming client requests
	lis, err := net.Listen(conf.GRPCHost.Network, conf.GRPCHost.String())
	if err != nil {
		log.Fatal(consts.UserServiceTag, "Failed to intialize TCP listener:", err.Error())
	}

	// implement all our methods/services in service/service.go THEN,

	// build: create an instance of gRPC server
	grpcServer := grpc.NewServer()

	// register our service implementation with gRPC server
	pb.RegisterUserServiceServer(grpcServer, &svc.Service{})
	log.Info(consts.UserServiceTag, "hwsc-user-svc started at:", conf.GRPCHost.String())

	// start gRPC server
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(consts.UserServiceTag, "Failed to serve:", err.Error())
	}
}
