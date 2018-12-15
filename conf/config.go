package conf

import (
	"fmt"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/micro/go-config"
	"github.com/micro/go-config/source/env"
)

const (
	confFilePath = "conf/json/config.dev.json"
	envPrefix    = "hosts"
)


var (
	// GRPCHost address and port of gRPC microservice
	GRPCHost Host

	// UserDB holds all DB information (c/n strings, dbName, collectionName)
	UserDB   UserDBHost
)

// init()
// set up some form of state on the initial startup of our program
// i.e: creating c/n to DBs, loading config files, initializing variable, etc.
// regardless of how many times package is imported, init is only called once
func init() {
	log.Info("Reading ENV variables")

	// create a new config
	conf := config.NewConfig()

	// convert environment variables to json format
	src := env.NewSource(
		env.WithPrefix(envPrefix),
	)

	// config.Load(): Load config from a file source
	// which is src that took environment variables and convert to json format
	// afterwards, conf is loaded with "src"
	if err := conf.Load(src); err != nil {
		log.Fatal("Failed to intialize configuration", err.Error())
	}

	// get gets the path target from loaded file
	// scan grabs the values from path target from the config file into a struct

	// in this case, scan "hosts" with "grpc"'s from config file
	// and copy all "grpc" properties to GRPCHost (type struct Host)
	if err := conf.Get("hosts", "grpc").Scan(&GRPCHost); err != nil {
		log.Fatal("Failed to get grpc configuration", err.Error())
	}

	// scan "hosts" prop "mongodb" properties from config file
	// and copy its props to UserDB struct
	if err := conf.Get("hosts", "mongodb").Scan(&UserDB); err != nil {
		log.Fatal("Failed to get mongodb configuration", err.Error())
	}
}

// Host represents a server
// `json:"address"` are key:value tags that can add meta information to structs
// there can be json tags, yaml tags, xml, bson, protobuf, etc.
// When json.Unmarshaling JSON file,
// takes the "address" JSON property, and put it in the Address field of Host
type Host struct {
	Address string `json:"address"`
	Port    string `json:"port"`
	Network string `json:"network"`
}

// function that receives pointer to Host
// Sprintf = string print format
func (h *Host) String() string {
	return fmt.Sprintf("%s:%s", h.Address, h.Port)
}

// UserDBHost represents the User database
// Writer address (primary connection string) for writing to user MongoDB server
// Reader connection string for reading from user MongoDB server
// Name is the database name
// Collection is the database's collection name
type UserDBHost struct {
	Writer     string `json:"writer"`
	Reader     string `json:"reader"`
	Name       string `json:"db"`
	Collection string `json:"collection"`
}
