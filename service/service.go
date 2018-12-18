package service

import (
	"flag"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	logger "github.com/hwsc-org/hwsc-logger/logger"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/mongodb/mongo-go-driver/bson"
	"github.com/mongodb/mongo-go-driver/mongo/options"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"sync"
	"time"
)

// Service struct type, implements the generated (pb file) UserServiceServer interface
type Service struct{}

// state of the service
type state uint32

// stateLocker synchronizes the state of the service
type stateLocker struct {
	lock                sync.RWMutex
	currentServiceState state
}

const (
	// available - service is ready and available for read/write
	available state = 0

	// unavailable - service is locked
	unavailable state = 1
)

var (
	// allows for global command line changing of deadlines, default deadline: 20,000 ms = 20 sec
	deadlineMsDB = flag.Int("deadline_ms", 20*1000, "Default deadline in milliseconds")

	serviceStateLocker stateLocker

	// converts the state of the service to a string
	serviceStateMap map[state]string

	// store the start time when service is executed (used for generating uuid with ulid)
	serviceStartTime time.Time
)

func init() {
	// executes command line parsing of deadlineMs, defaults to 20,000 ms
	// flag.Parse();

	serviceStateLocker = stateLocker{
		currentServiceState: available,
	}

	serviceStateMap = map[state]string{
		available:   "Available",
		unavailable: "Unavailable",
	}

	serviceStartTime = time.Unix(time.Now().Unix(), 0)
}

// GetStatus gets the current status of the service
// Returns status code int and status code text, and any connection errors
func (s *Service) GetStatus(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("GetStatus")

	// Lock the state for reading and defer unlocks the state before function exits
	serviceStateLocker.lock.RLock()
	defer serviceStateLocker.lock.RUnlock()

	logger.Info("Service state:", serviceStateMap[serviceStateLocker.currentServiceState])
	if serviceStateLocker.currentServiceState == unavailable {
		return &pb.UserResponse{
			Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
			Message: codes.Unavailable.String(),
		}, nil
	}

	//Check if mongo clients are found and connected
	if err := refreshMongoConnection(mongoClientReader); err != nil {
		logger.Error("Failed to ping and reconnect mongo reader server:", err.Error())
		return &pb.UserResponse{
			Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
			Message: codes.Unavailable.String(),
		}, nil
	}

	if err := refreshMongoConnection(mongoClientWriter); err != nil {
		logger.Error("Failed to ping and reconnect mongo writer server:", err.Error())
		return &pb.UserResponse{
			Status:  &pb.UserResponse_Code{Code: uint32(codes.Unavailable)},
			Message: codes.Unavailable.String(),
		}, nil
	}

	return &pb.UserResponse{
		Status:  &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
	}, nil
}

// CreateUser creates a new user document and inserts it to user DB
func (s *Service) CreateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	logger.RequestService("CreateUser")

	// get User object
	user := req.GetUser()
	if user == nil {
		logger.Error(errNilRequestUser.Error())
		return nil, status.Error(codes.InvalidArgument, errNilRequestUser.Error())
	}

	// look through mongo user collection to check for email duplication
	collection := mongoClientWriter.Database(conf.UserDB.Name).Collection(conf.UserDB.Collection)
	filter := bson.M{"email": user.Email}

	limit := int64(1)
	docCount, err := collection.CountDocuments(context.TODO(), filter, &options.CountOptions{Limit: &limit})
	if err != nil {
		logger.Error("CountDocuments:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	if docCount > 0 {
		logger.Error(errEmailTaken.Error())
		return nil, status.Error(codes.Unavailable, errEmailTaken.Error())
	}

	// create unique user id using ulid
	// TODO service will crash if ulid can't generate a new unique id, will this ever occur?
	uuid := generateUUID()

	// hash the hashed password using bcrypt
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		logger.Error("hashPassword:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	// set generated uuid and hashed password
	// TODO am I allowed to directly mutate this User object?
	user.Uuid = uuid
	user.Password = hashedPassword
	user.JoinedTimestamp = time.Now().Unix()

	// create new document and insert to mongo user collection
	res, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		logger.Error("InsertOne:", err.Error())
		return nil, status.Error(codes.Unknown, err.Error())
	}

	log.Printf("[INFO] Success inserting new user _id: %v\n", res.InsertedID)

	return &pb.UserResponse{
		Status: &pb.UserResponse_Code{Code: uint32(codes.OK)},
		Message: codes.OK.String(),
		User: user,
	}, nil
}

//// DeleteUser deletes a user document in user DB
//func (s *Service) DeleteUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("DeleteUser")
//	return &pb.UserResponse{}, nil
//}
//
//// UpdateUser updates a user document in user DB
//func (s *Service) UpdateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("UpdateUser")
//	return &pb.UserResponse{}, nil
//}
//
//// AuthenticateUser goes through user DB collection and tries to find matching email/password
//func (s *Service) AuthenticateUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("AuthenticateUser")
//	return &pb.UserResponse{}, nil
//}
//
//// ListUsers returns the user DB collection
//func (s *Service) ListUsers(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("ListUsers")
//	return &pb.UserResponse{}, nil
//}
//
//// GetUser returns a user document in user DB
//func (s *Service) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("GetUser")
//	return &pb.UserResponse{}, nil
//}
//
//// ShareDocument updates user/s documents shared_to_me field in user DB
//func (s *Service) ShareDocument(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
//	//TODO
//	log.RequestService("ShareDocument")
//	return &pb.UserResponse{}, nil
//}
