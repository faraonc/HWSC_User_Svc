package conf

import (
	"fmt"
	log "github.com/hwsc-org/hwsc-logging/logger"
	"github.com/micro/go-config"
	"github.com/micro/go-config/source/file"
)

const (
	confFilePath = "conf/json/config.dev.json"
)

// GRPCHost address and port of gRPC microservice
// UserDB holds all DB information (c/n strings, dbName, collectionName)

var (
	GRPCHost Host
	UserDB   UserDBHost
)

// init()
// set up some form of state on the initial startup of our program
// i.e: creating c/n to DBs, loading config files, initializing variable, etc.
// regardless of how many times package is imported, init is only called once
func init() {
	// config.Load(): Load config from a file source
	// file extension determines config format
	// in this case, load json config file
	var err error
	err = config.Load(file.NewSource(file.WithPath(confFilePath)))
	if err != nil {
		// TODO provide config path to use with unit test?
		log.Fatal("Failed to initialize conf file", err.Error())
	}

	// get gets the path target from config file
	// scan grabs the values from path target from the config file into a struct

	// in this case, scan "hosts" "grpc-server" from config file
	// and copy all "grpc-server" properties to GRPCHost (type struct Host)
	// &GRPCHost = reference to GRPCHost (address), similar to pass-by-reference
	err = config.Get("hosts", "grpc-server").Scan(&GRPCHost)
	if err != nil {
		log.Fatal("Failed to scan conf file", err.Error())
	}

	// scan "hosts" prop "mongodb-document" properties from config file
	// and copy its props to UserDB struct
	err = config.Get("hosts", "mongodb-user").Scan(&UserDB)
	if err != nil {
		log.Fatal("Failed to scan conf file", err.Error())
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
	Writer     string `json:"mongodb-writer"`
	Reader     string `json:"mongodb-reader"`
	Name       string `json:"db"`
	Collection string `json:"collection"`
}
