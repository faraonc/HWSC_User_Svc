package service

import (
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxFirstNameLength  = 32
	maxLastNameLength   = 32
	daysInOneWeek       = 7
	domainName          = "localhost"
	verifyEmailLinkStub = "verify-email?token"
)

var (
	keyGenLocker        sync.Mutex
	uuidLocker          sync.Mutex
	multiSpaceRegex     = regexp.MustCompile(`[\s\p{Zs}]{2,}`)
	nameValidCharsRegex = regexp.MustCompile(`^[[:alpha:]]+((['.\s-][[:alpha:]\s])?[[:alpha:]]*)*$`)
)

func (s *stateLocker) isStateAvailable() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.currentServiceState != available {
		return false
	}

	return true
}

func validateUser(user *pblib.User) error {
	if user == nil {
		return consts.ErrNilRequestUser
	}

	if err := validateFirstName(user.GetFirstName()); err != nil {
		return err
	}
	if err := validateLastName(user.GetLastName()); err != nil {
		return err
	}
	if err := validateEmail(user.GetEmail()); err != nil {
		return err
	}
	if err := validatePassword(user.GetPassword()); err != nil {
		return consts.ErrInvalidPassword
	}
	if err := validateOrganization(user.GetOrganization()); err != nil {
		return err
	}
	return nil
}

func validatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return consts.ErrInvalidPassword
	}
	return nil
}

func validateFirstName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return consts.ErrInvalidUserFirstName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxFirstNameLength || !nameValidCharsRegex.MatchString(name) {
		return consts.ErrInvalidUserFirstName
	}

	return nil
}

func validateLastName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return consts.ErrInvalidUserLastName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxLastNameLength || !nameValidCharsRegex.MatchString(name) {
		return consts.ErrInvalidUserLastName
	}

	return nil
}

func validateOrganization(name string) error {
	if name == "" {
		return consts.ErrInvalidUserOrganization
	}
	return nil
}

// generateUUID generates a unique user ID using ulid package based on currentTime.
// Returns a lower cased string type of generated ulid.ULID.
func generateUUID() (string, error) {
	uuidLocker.Lock()
	defer uuidLocker.Unlock()

	t := time.Now().UTC()
	entropy := rand.New(rand.NewSource(t.UnixNano()))

	id, err := ulid.New(ulid.Timestamp(t), entropy)
	if err != nil {
		return "", err
	}

	return strings.ToLower(id.String()), nil
}

// hashPassword hashes and salts provided password.
// Returns string hashed password.
func hashPassword(password string) (string, error) {
	if password == "" || strings.TrimSpace(password) != password {
		return "", consts.ErrInvalidPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// comparePassword compares hashedPassword retrieved from DB and the password from User request.
// Returns nil if match, error if not match or error from bcrypt.
func comparePassword(hashedPassword string, password string) error {
	if hashedPassword == "" || password == "" {
		return consts.ErrInvalidPassword
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return err
	}

	return nil
}

// setCurrentSecretOnce checks if currAuthSecret is set, if not,
// retrieves the active secret key found in secrets table.
// Returns any db encountered error, or nil if secret is already set or no error.
func setCurrentSecretOnce() error {
	if currAuthSecret != nil {
		return nil
	}

	var err error
	currAuthSecret, err = getActiveSecretRow()
	if err != nil {
		return err
	}

	return nil
}

// generateEmailVerifyLink generates a verification email link.
// Used to be sent as part of verification email sent to new users or users updating their email.
// Returns error if token string is empty.
func generateEmailVerifyLink(token string) (string, error) {
	if token == "" {
		return "", authconst.ErrEmptyToken
	}

	link := fmt.Sprintf("%s/%s=%s", domainName, verifyEmailLinkStub, token)

	return link, nil
}

// getAuthIdentification gets or generates the latest AuthToken for the User.
// Returns the identification or error.
func getAuthIdentification(retrievedUser *pblib.User) (*pblib.Identification, error) {
	if retrievedUser == nil {
		return nil, consts.ErrStatusNilRequestUser
	}
	var identification *pblib.Identification

	existingToken, err := getAuthTokenRow(retrievedUser.GetUuid())
	if err == nil {
		if existingToken.permission != retrievedUser.PermissionLevel {
			return nil, consts.ErrStatusPermissionMismatch
		}
		identification = &pblib.Identification{
			Token:  existingToken.token,
			Secret: existingToken.secret,
		}
	} else {
		permissionLevel := auth.PermissionEnumMap[retrievedUser.GetPermissionLevel()]

		// build token header, body, secret
		header := &auth.Header{
			Alg:      auth.AlgorithmMap[permissionLevel],
			TokenTyp: auth.Jwt,
		}
		body := &auth.Body{
			UUID:                retrievedUser.GetUuid(),
			Permission:          permissionLevel,
			ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(authTokenExpirationTime)).Unix(),
		}

		if err := setCurrentSecretOnce(); err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		newToken, err := auth.NewToken(header, body, currAuthSecret)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// insert token into db for auditing
		if err := insertAuthToken(newToken, header, body, currAuthSecret); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		identification = &pblib.Identification{
			Token:  newToken,
			Secret: currAuthSecret,
		}
	}

	return identification, nil
}

// newAuthIdentification generates a new AuthToken for user.
// Returns the new identification or error.
func newAuthIdentification(oldHeader *auth.Header, oldBody *auth.Body) (*pblib.Identification, error) {
	if err := auth.ValidateHeader(oldHeader); err != nil {
		return nil, err
	}
	if err := auth.ValidateBody(oldBody); err != nil {
		return nil, err
	}

	header := &auth.Header{
		Alg:      oldHeader.Alg,
		TokenTyp: oldHeader.TokenTyp,
	}

	body := &auth.Body{
		UUID:                oldBody.UUID,
		Permission:          oldBody.Permission,
		ExpirationTimestamp: time.Now().UTC().Add(time.Hour * time.Duration(authTokenExpirationTime)).Unix(),
	}

	if err := setCurrentSecretOnce(); err != nil {
		return nil, err
	}

	newToken, err := auth.NewToken(header, body, currAuthSecret)
	if err != nil {
		return nil, err
	}

	// insert token into db for auditing
	if err := insertAuthToken(newToken, header, body, currAuthSecret); err != nil {
		return nil, err
	}

	identification := &pblib.Identification{
		Token:  newToken,
		Secret: currAuthSecret,
	}

	return identification, nil
}
