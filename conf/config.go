package conf

import (
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/hosts"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/micro/go-config"
	"github.com/micro/go-config/source/env"
)

const (
	environmentVariablePrefix = "hosts"
)

var (
	// GRPCHost contains server configs grabbed from env vars
	GRPCHost hosts.Host

	// UserDB contains user database configs grabbed from env vars
	UserDB hosts.UserDBHost

	// EmailHost contains smtp configs grabbed from env vars
	EmailHost hosts.SMTPHost

	// DummyAccount reads from environment variables, and it is used for creating accounts
	DummyAccount pblib.User
)

func init() {
	logger.Info(consts.UserServiceTag, "Reading ENV variables")

	// create a new config
	conf := config.NewConfig()

	// convert environment variables to json format
	src := env.NewSource(
		env.WithPrefix(environmentVariablePrefix),
	)

	// config.Load(): Load config from a file source
	if err := conf.Load(src); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to initialize configuration", err.Error())
	}

	// get gets the path target from loaded file
	// scan grabs the values from path target from the config file into a struct
	// scan "hosts" with "grpc" props from config file & copy all "grpc" prop values to GRPCHost struct
	if err := conf.Get("hosts", "user").Scan(&GRPCHost); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get grpc configuration", err.Error())
	}

	// scan "hosts" prop "postgres" from environmental variables & copy values to UserDB struct
	if err := conf.Get("hosts", "postgres").Scan(&UserDB); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get psql configuration", err.Error())
	}

	if err := conf.Get("hosts", "smtp").Scan(&EmailHost); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get smtp email configurations", err.Error())
	}

	if err := conf.Get("hosts", "dummy").Scan(&DummyAccount); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get dummy account configurations", err.Error())
	}
}
