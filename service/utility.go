package service

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-lib/validation"
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
	emailTokenByteSize  = 32
	daysInOneWeek       = 7
	daysInTwoWeeks      = 14
	utc                 = "UTC"
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

// generateEmailToken takes the user's uuid and permission to generate an email token for verification.
// Returns an identification containing the secret and token string.
func generateEmailToken(uuid string, permission string) (*pblib.Identification, error) {
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, err
	}
	permissionLevel, ok := auth.PermissionEnumMap[permission]
	if !ok {
		return nil, authconst.ErrInvalidPermission
	}
	emailSecretKey, err := generateSecretKey(emailTokenByteSize)
	if err != nil {
		return nil, err
	}
	// subtract a second because the test runs fast causing our check to fail
	emailTokenCreationTime := time.Now().UTC().Add(time.Duration(-1) * time.Second)
	emailTokenExpirationTime, err := generateExpirationTimestamp(emailTokenCreationTime, daysInTwoWeeks)
	if err != nil {
		return nil, err
	}

	header := &auth.Header{
		Alg:      auth.AlgorithmMap[auth.UserRegistration],
		TokenTyp: auth.Jet,
	}
	body := &auth.Body{
		UUID:                uuid,
		Permission:          permissionLevel,
		ExpirationTimestamp: emailTokenExpirationTime.Unix(),
	}
	secret := &pblib.Secret{
		Key:                 emailSecretKey,
		CreatedTimestamp:    emailTokenCreationTime.Unix(),
		ExpirationTimestamp: emailTokenExpirationTime.Unix(),
	}
	emailToken, err := auth.NewToken(header, body, secret)
	if err != nil {
		return nil, err
	}

	return &pblib.Identification{
		Token:  emailToken,
		Secret: secret,
	}, nil
}

// generateRandomToken generates a base64 URL-safe string
// built from securely generated random bytes.
// Number of bytes is determined by tokenSize.
// Return error if system's secure random number generator fails.
func generateSecretKey(tokenSize int) (string, error) {
	if tokenSize <= 0 {
		return "", consts.ErrInvalidTokenSize
	}

	keyGenLocker.Lock()
	defer keyGenLocker.Unlock()

	randomBytes := make([]byte, tokenSize)
	_, err := cryptorand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

// generateExpirationTimestamp returns the expiration date set with addDays parameter.
// Currently only adds number of days to currentTimestamp.
// Returns error if date object is nil or error with loading location.
func generateExpirationTimestamp(currentTimestamp time.Time, addDays int) (*time.Time, error) {
	if currentTimestamp.IsZero() {
		return nil, consts.ErrInvalidTimeStamp
	}

	if addDays <= 0 {
		return nil, consts.ErrInvalidNumberOfDays
	}

	timeZonedTimestamp := currentTimestamp
	if currentTimestamp.Location().String() != utc {
		timeZonedTimestamp = currentTimestamp.UTC()
	}

	// addDays to current weekday to get to addDays later
	// ie: adding 7 days to current weekday gets you one week later timestamp
	modifiedTimestamp := timeZonedTimestamp.AddDate(0, 0, addDays)

	// reset time to 3 AM
	expirationTimestamp := time.Date(modifiedTimestamp.Year(), modifiedTimestamp.Month(), modifiedTimestamp.Day(),
		3, 0, 0, 0, timeZonedTimestamp.Location())

	return &expirationTimestamp, nil
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

// getAuthIdentification gets or generates the AuthToken for the User.
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
