package service

import (
	"github.com/oklog/ulid"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"strings"
)

// generateUUID generates a unique user ID using ulid package based on serviceStartTime
// returns a lower cased string type of generated ulid.ULID
func generateUUID() string {
	entropy := ulid.Monotonic(rand.New(rand.NewSource(serviceStartTime.UnixNano())), 0)

	uuid := ulid.MustNew(ulid.Timestamp(serviceStartTime), entropy)
	return strings.ToLower(uuid.String())
}


func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}