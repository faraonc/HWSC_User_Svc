package service

import (
	"database/sql"
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"google.golang.org/grpc/codes"
	// database/sql uses this library indirectly
	_ "github.com/lib/pq"
	"os"
	"os/signal"
	"syscall"
)

const (
	dbDriverName = "postgres"
)

var (
	connectionString    string
	postgresDB          *sql.DB
	postgresUnavailable *pb.UserResponse
)

func init() {
	postgresUnavailable = &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
		Message: codes.Unavailable.String(),
	}

	log.Info("Connecting to postgres DB")

	// initialize connection string
	connectionString = fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s sslmode=verify-full",
		conf.UserDB.Host, conf.UserDB.User, conf.UserDB.Password, conf.UserDB.Name)

	// intialize connection object
	var err error
	postgresDB, err = sql.Open(dbDriverName, connectionString)
	if err != nil {
		log.Fatal("Failed to intialize connection object:", err.Error())
	}

	// verify connection is alive, establishing connection if necessary
	err = postgresDB.Ping()
	if err != nil {
		log.Fatal("Ping failed, cannot establish connection:", err.Error())
	}

	// Handle Terminate Signal(Ctrl + C) gracefully
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info("Disconnecting postgres DB")
		if postgresDB != nil {
			_ = postgresDB.Close()
		}
		log.Fatal("hwsc-user-svc terminated")
	}()
}

// refreshDBConnection verifies if connection is alive, ping will establish c/n if necessary
// Returns response object if ping failed to reconnect
func refreshDBConnection() *pb.UserResponse {
	if postgresDB == nil {
		var err error
		postgresDB, err = sql.Open(dbDriverName, connectionString)
		if err != nil {
			return postgresUnavailable
		}
	}

	if err := postgresDB.Ping(); err != nil {
		_ = postgresDB.Close()
		log.Error("Failed to ping and reconnect to postgres db:", err.Error())

		return postgresUnavailable
	}

	return nil
}
