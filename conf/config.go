package conf

import (
	"fmt"
	"github.com/hwsc-org/hwsc-lib/logger"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/micro/go-config"
	"github.com/micro/go-config/source/env"
)

const (
	environmentVariablePrefix = "hosts"
)

// Host contains server configuration
// `json:"address"` are key:value tags that can add meta information to structs
// there can be json tags, yaml tags, xml, bson, protobuf, etc.
// When json.Unmarshaling JSON file,
// takes the "address" JSON property, and put it in the Address field of Host
type Host struct {
	Address string `json:"address"`
	Port    string `json:"port"`
	Network string `json:"network"`
}

// UserDBHost contains User database configurations
type UserDBHost struct {
	Host     string `json:"host"`
	Name     string `json:"db"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// SMTPHost contains SMTP email configurations
type SMTPHost struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	// GRPCHost contains server configs grabbed from env vars
	GRPCHost Host

	// UserDB contains user database configs grabbed from env vars
	UserDB UserDBHost

	// EmailHost contains smtp configs grabbed from env vars
	EmailHost SMTPHost
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

	// scan "hosts" prop "psql" from environmental variables & copy values to UserDB struct
	if err := conf.Get("hosts", "psql").Scan(&UserDB); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get psql configuration", err.Error())
	}

	if err := conf.Get("hosts", "smtp").Scan(&EmailHost); err != nil {
		logger.Fatal(consts.UserServiceTag, "Failed to get smtp email configurations", err.Error())
	}
}

// String prints readable address and port using
func (h *Host) String() string {
	return fmt.Sprintf("%s:%s", h.Address, h.Port)
}
