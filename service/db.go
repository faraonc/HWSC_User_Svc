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
	var err error

	mongoClientReader, err = dialMongoDB(&conf.UserDB.Reader, mongoReader)
	if err != nil {
		log.Fatal("Failed to connect to server", mongoReader, "server:", err.Error())
	}

	mongoClientWriter, err = dialMongoDB(&conf.UserDB.Writer, mongoWriter)
	if err != nil {
		log.Fatal("Failed to connect to", mongoWriter, "server:", err.Error())
	}

	// Handle Terminate Signal(Ctrl + C)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		_ = disconnectMongoClient(mongoClientReader, mongoReader)
		_ = disconnectMongoClient(mongoClientWriter, mongoWriter)
		fmt.Println()
		log.Fatal("hwsc-user-svc terminated")
	}()
}

// connectToMongo creates a new client, checks connection, & monitors the specified Mongo server
// Returns connected client or errors
func dialMongoDB(uri *string, clientType string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, *uri)
	if err == nil {
		// connect is not a blocking call, ping confirms that db is indeed found and connected
		err = pingMongoClient(client, clientType)
		if err != nil {
			return nil, err
		}
		log.Info("Connected to", clientType, "server")
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

	log.Info("Disconnecting client", clientType)

	return client.Disconnect(ctx)
}

// pingMongoClient checks if client is found and connected to server
// Returns connection errors
func pingMongoClient(client *mongo.Client, clientType string) error {
	if client == nil {
		return errNilMongoClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Ping(ctx, nil)
	if err != nil {
		log.Info("Ping failed for", clientType, ":", err.Error())
	}

	return err
}
