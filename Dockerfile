# This dockerfile contains instructions to build an image for hwsc-user-svc
# later, this image can be ran in a container to run the program

# FROM instruction specifies the base image from which we are building
FROM golang:1.12.0

# WORKDIR instruction changes current directory to /go
WORKDIR $GOPATH/

# RUN a git clone shell command in current directory /go
RUN git clone https://github.com/hwsc-org/hwsc-user-svc.git

# change directory to the cloned directory
WORKDIR $GOPATH/hwsc-user-svc

# download dependencies from go.mod and go.sum files found in hwsc-user-svc directory
RUN go mod download

# compile main.go and create an executable file and move it to $GOPATH/bin
# and cache all non-main packages which are imported to $GOPATH/pkg
# the cache will be used in the next compile if it hasn't been changed
RUN go install

# set the command and its parameters that will be executed first when a container is run
# in this case, run the executable file called "hwsc-user-svc"
ENTRYPOINT ["/go/bin/hwsc-user-svc"]

# EXPOSE instruction informs Docker that the container
# listens on specified network port 50052 at runtime (default listening on TCP)
EXPOSE 50052
