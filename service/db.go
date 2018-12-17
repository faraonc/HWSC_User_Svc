package service

import (
	"fmt"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/mongodb/mongo-go-driver/mongo"
	"golang.org/x/net/context"
	"os"
	"os/signal"
	"syscall"
)

var (
	mongoClientReader *mongo.Client
	mongoClientWriter *mongo.Client
)

const (
	mongoReader = "mongo reader"
	mongoWriter = "mongo writer"
)

func init() {
	log.Info("Connecting to mongo databases")

	var err error
	mongoClientReader, err = dialMongoDB(&conf.UserDB.Reader)
	if err != nil {
		log.Fatal("Failed to connect to mongo reader server:", err.Error())
	}

	mongoClientWriter, err = dialMongoDB(&conf.UserDB.Writer)
	if err != nil {
		log.Fatal("Failed to connect to mongo writer server:", err.Error())
	}

	// Handle Terminate Signal(Ctrl + C)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info("Disconnecting mongo databases")
		_ = disconnectMongoClient(mongoClientReader)
		_ = disconnectMongoClient(mongoClientWriter)
		fmt.Println()
		log.Fatal("hwsc-user-svc terminated")
	}()
}

// connectToMongo creates a new client, checks connection, & monitors the specified Mongo server
// Returns connected client or errors
func dialMongoDB(uri *string) (*mongo.Client, error) {
	client, err := mongo.Connect(context.TODO(), *uri)
	if err != nil {
		return nil, err
	}

	if err := client.Ping(context.TODO(), nil); err != nil {
		return nil, err
	}

	return client, nil
}

// disconnectMongoClient closes clients connection to server
// Returns disconnection errors
func disconnectMongoClient(client *mongo.Client) error {
	if client == nil {
		return errNilMongoClient
	}

	return client.Disconnect(context.TODO())
}

// pingAndRefreshMongoConnection pings for connection, tries to redial
func refreshMongoConnection(client *mongo.Client) error {
	if client == nil {
		return errNilMongoClient
	}
	if err := client.Ping(context.TODO(), nil); err != nil {
		if err := client.Connect(context.TODO()); err != nil {
			return err
		}
	}

	// TODO gives error if used with disconnect
	//if err := pingMongoClient(client); err != nil {
	//	return err
	//}
	return nil
}
