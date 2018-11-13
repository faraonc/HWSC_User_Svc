package main

import (
	pb "github.com/faraonc/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/faraonc/hwsc-logging/logger"
	"github.com/faraonc/hwsc-user-svc/conf"
	svc "github.com/faraonc/hwsc-user-svc/service"
	"google.golang.org/grpc"
	"net"
)

func main() {
	log.Info("hwsc-user-svc initiating...")

	// make TCP listener, listen for incoming client requests
	lis, err := net.Listen(conf.GRPCHost.Network, conf.GRPCHost.String())
	if err != nil {
		log.Fatal("Failed to intialize TCP listener", err.Error())
	}

	// implement all our methods/services in service/service.go THEN,

	// build: create an instance of gRPC server
	grpcServer := grpc.NewServer()

	// register our service implementation with gRPC server
	pb.RegisterUserServiceServer(grpcServer, &svc.Service{})
	log.Info("hwsc-user-svc at", conf.GRPCHost.Address, "...")

	// start gRPC server
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal("Failed to serve", err.Error())
	}
}
