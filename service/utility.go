package service

import (
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const (
	maxFirstNameLength = 32
	maxLastNameLength  = 32
	emailTokenBytes    = 32
)

var (
	multiSpaceRegex     = regexp.MustCompile(`[\s\p{Zs}]{2,}`)
	nameValidCharsRegex = regexp.MustCompile(`^[[:alpha:]]+((['.\s-][[:alpha:]\s])?[[:alpha:]]*)*$`)
)

func (s *stateLocker) isStateAvailable() bool {
	//TODO need to test for read race conditions
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.currentServiceState != available {
		return false
	}

	return true
}

func validateUser(user *pb.User) error {
	if err := validateFirstName(user.GetFirstName()); err != nil {
		return err
	}
	if err := validateLastName(user.GetLastName()); err != nil {
		return err
	}
	if err := validateEmail(user.GetEmail()); err != nil {
		return err
	}
	if password := user.GetPassword(); password == "" || strings.TrimSpace(password) != password {
		return errInvalidPassword
	}
	if err := validateOrganization(user.GetOrganization()); err != nil {
		return err
	}
	return nil
}

func validateFirstName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errInvalidUserFirstName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxFirstNameLength || !nameValidCharsRegex.MatchString(name) {
		return errInvalidUserFirstName
	}

	return nil
}

func validateLastName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errInvalidUserLastName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxLastNameLength || !nameValidCharsRegex.MatchString(name) {
		return errInvalidUserLastName
	}

	return nil
}

func validateOrganization(name string) error {
	if name == "" {
		return errInvalidUserOrganization
	}
	return nil
}

// generateUUID generates a unique user ID using ulid package based on currentTime
// returns a lower cased string type of generated ulid.ULID
func (u *uuidLocker) generateUUID() error {
	u.lock.Lock()
	defer u.lock.Unlock()

	t := time.Now().UTC()
	entropy := rand.New(rand.NewSource(t.UnixNano()))

	id, err := ulid.New(ulid.Timestamp(t), entropy)
	if err != nil {
		return err
	}

	u.uuid = strings.ToLower(id.String())

	return nil
}

func validateUUID(uuid string) error {
	if uuid == "" {
		return errInvalidUUID
	}

	id, err := ulid.ParseStrict(strings.ToUpper(uuid))
	if err != nil || strings.ToLower(id.String()) != uuid {
		return errInvalidUUID
	}

	return nil
}

// hashPassword hashes and salts provided password
// returns stringified hashed password
func hashPassword(password string) (string, error) {
	if password == "" || strings.TrimSpace(password) != password {
		return "", errInvalidPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}
