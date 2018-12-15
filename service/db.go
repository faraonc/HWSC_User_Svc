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
	reader = "reader"
	writer = "writer"
)

func init() {
	var err error

	mongoClientReader, err = dialMongoDB(&conf.UserDB.Reader)
	if err != nil {
		log.Fatal("Failed to connect to reader mongo server:", err.Error())
	} else {
		log.Info("Connected to reader mongo server")
	}

	mongoClientWriter, err = dialMongoDB(&conf.UserDB.Writer)
	if err != nil {
		log.Fatal("Failed to connect to mongo writer server:", err.Error())
	} else {
		log.Info("Connected to writer mongo server")
	}

	// Handle Terminate Signal(Ctrl + C)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		_ = disconnectMongoClient(mongoClientReader, reader)
		_ = disconnectMongoClient(mongoClientWriter, writer)
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
	if err == nil {
		// connect is not a blocking call, ping confirms that db is indeed found and connected
		err = pingMongoClient(client)
		if err != nil {
			return nil, err
		}
	}

	return client, err
}

// disconnectMongoClient closes clients connection to server
// Returns disconnection errors
func disconnectMongoClient(client *mongo.Client, clientType string) error {
	if client == nil {
		return errNilMongoClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Info("Disconnecting", clientType, "mongo client")

	return client.Disconnect(ctx)
}

// pingMongoClient checks if client is found and connected to server
// Returns connection errors
func pingMongoClient(client *mongo.Client) error {
	if client == nil {
		return errNilMongoClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return client.Ping(ctx, nil)
}
