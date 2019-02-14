package main

import (
	pbsvc "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/user"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	svc "github.com/hwsc-org/hwsc-user-svc/service"
	"google.golang.org/grpc"
	"net"
)

func main() {
	logger.Info(consts.UserServiceTag, "hwsc-user-svc initiating...")

	// make TCP listener, listen for incoming client requests
	lis, err := net.Listen(conf.GRPCHost.Network, conf.GRPCHost.String())
	if err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to intialize TCP listener:", err.Error())
	}

	// implement all our methods/services in service/service.go THEN,

	// build: create an instance of gRPC server
	grpcServer := grpc.NewServer()

	// register our service implementation with gRPC server
	pbsvc.RegisterUserServiceServer(grpcServer, &svc.Service{})
	logger.Info(consts.UserServiceTag, "hwsc-user-svc started at:", conf.GRPCHost.String())

	// start gRPC server
	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to serve:", err.Error())
	}
}
