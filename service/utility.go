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
	maxEmailLength     = 320
)

var (
	multiSpaceRegex     = regexp.MustCompile(`[\s\p{Zs}]{2,}`)
	nameValidCharsRegex = regexp.MustCompile(`^[[:alpha:]]+((['.\s-][[:alpha:]\s])?[[:alpha:]]*)*$`)

	// tests empty string, @ symbol in between, at least 3 chars
	emailRegex = regexp.MustCompile(`.+@.+`)
)

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
	if user.GetPassword() == "" {
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

func validateEmail(email string) error {
	if len(email) > maxEmailLength || !emailRegex.MatchString(email) {
		return errInvalidUserEmail
	}

	return nil
}

func validateOrganization(name string) error {
	if name == "" {
		return errInvalidUserOrganization
	}
	return nil
}

// TODO synchronize inside this function
// generateUUID generates a unique user ID using ulid package based on currentTime
// returns a lower cased string type of generated ulid.ULID
func generateUUID() (string, error) {
	t := time.Now().UTC()
	entropy := rand.New(rand.NewSource(t.UnixNano()))

	id, err := ulid.New(ulid.Timestamp(t), entropy)
	if err != nil {
		return "", err
	}

	return strings.ToLower(id.String()), nil
}

// hashPassword hashes and salts provided string
// returns stringified hashed password
func hashPassword(password string) (string, error) {
	if password == "" {
		return "", errEmptyPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
