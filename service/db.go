package service

import (
	"context"
	"fmt"
	log "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/mongodb/mongo-go-driver/mongo"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, *uri)
	if err != nil {
		return nil, err
	}

	if err := pingMongoClient(client); err != nil {
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

	//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//defer cancel()

	return client.Disconnect(context.Background())
}

// pingMongoClient checks if client is found and connected to server
// Returns connection errors
func pingMongoClient(client *mongo.Client) error {
	if client == nil {
		return errNilMongoClient
	}

	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()

	if err := client.Ping(context.Background(), nil); err != nil {
		return err
	}

	return nil
}

// pingAndRefreshMongoConnection pings for connection, tries to redial
//func pingAndRefreshMongoConnection(client *mongo.Client) error {
//	if client == nil {
//		return errNilMongoClient
//	}
//	if err := pingMongoClient(client); err == nil {
//		return nil
//	}
//	if err := client.Connect(context.TODO()); err != nil {
//		return err
//	}
//	if err := pingMongoClient(client); err != nil {
//		return err
//	}
//	return nil
//}