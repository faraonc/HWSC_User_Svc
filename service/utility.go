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

func validateUser(user *pb.User) (string, error) {
	if str, err := validateFirstName(user.GetFirstName()); err != nil {
		return str, err
	}
	if str, err := validateLastName(user.GetLastName()); err != nil {
		return str, err
	}
	if str, err := validateEmail(user.GetEmail()); err != nil {
		return str, err
	}
	if user.GetPassword() == "" {
		return "User Password is blank", errInvalidPassword
	}
	if str, err := validateOrganization(user.GetOrganization()); err != nil {
		return str, err
	}
	return "", nil
}

func validateFirstName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "User first name is blank", errInvalidUserFirstName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxFirstNameLength {
		return "User first name exceeds max length", errInvalidUserFirstName
	}

	if !nameValidCharsRegex.MatchString(name) {
		return "User first name contains invalid characters", errInvalidUserFirstName
	}

	return "", nil
}

func validateLastName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "User last name is blank", errInvalidUserLastName
	}

	name = multiSpaceRegex.ReplaceAllString(name, " ")
	if len(name) > maxLastNameLength {
		return "User last name exceeds max length", errInvalidUserLastName
	}

	if !nameValidCharsRegex.MatchString(name) {
		return "User last name contains invalid characters", errInvalidUserLastName
	}

	return "", nil
}

func validateEmail(email string) (string, error) {
	if len(email) > maxEmailLength {
		return "User Email exceeds max length", errInvalidUserEmail
	}

	if !emailRegex.MatchString(email) {
		return "User Email is either: len < 3 || symbol @ is misplaced", errInvalidUserEmail
	}
	return "", nil
}

func validateOrganization(name string) (string, error) {
	if name == "" {
		return "User Organization is blank", errInvalidUserOrganization
	}
	return "", nil
}

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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
