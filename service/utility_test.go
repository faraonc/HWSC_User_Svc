package service

import (
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-user-svc/proto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateUser(t *testing.T) {
	// valid
	validTest := pb.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid first name
	invalidFirstName := pb.User{
		FirstName:    "",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid last name
	invalidLastName := pb.User{
		FirstName:    "Lisa",
		LastName:     "",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid email
	invalidEmail := pb.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "@",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid password
	invalidPassword := pb.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "",
		Organization: "uwb",
	}

	// invalid organization
	invalidOrg := pb.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "",
	}

	cases := []struct {
		user     *pb.User
		isExpErr bool
		expMsg   string
	}{
		{&validTest, false, ""},
		{&invalidFirstName, true, errInvalidUserFirstName.Error()},
		{&invalidLastName, true, errInvalidUserLastName.Error()},
		{&invalidEmail, true, errInvalidUserEmail.Error()},
		{&invalidPassword, true, errInvalidPassword.Error()},
		{&invalidOrg, true, errInvalidUserOrganization.Error()},
	}

	for _, c := range cases {
		err := validateUser(c.user)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
		} else {
			assert.Equal(t, "", c.expMsg)
			assert.Nil(t, err)
		}
	}
}

func TestValidateFirstName(t *testing.T) {
	exceedMaxLengthName := "uAaxAYexAkSHzirzlLJGKtjrbWnMkaryQ"
	reachMaxLengthTrailingSpaces := "   jjYnNXQewvJvyNNVeyZPSJRazTLAiFXk   "
	reachMaxLengthSpacesBetween := "   jjYnNXQewvJvyN  VeyZPSJRaz  LAiFXk   "

	cases := []struct {
		name     string
		isExpErr bool
	}{
		{"", true},
		{exceedMaxLengthName, true},
		{"Hello-.", true},
		{"Hell O .", true},
		{"Hell O-", true},
		{"Hello%f@k", true},
		{"Hello", false},
		{"Hell-O", false},
		{"Hell O", false},
		{"He.llo Can You Hear Me", false},
		{"Hell'o World", false},
		{reachMaxLengthTrailingSpaces, false},
		{reachMaxLengthSpacesBetween, false},
	}

	for _, c := range cases {
		err := validateFirstName(c.name)

		if c.isExpErr {
			assert.EqualError(t, err, errInvalidUserFirstName.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestValidateLastName(t *testing.T) {
	exceedMaxLengthName := "uAaxAYexAkSHzirzlLJGKtjrbWnMkaryQ"
	reachMaxLengthTrailingSpaces := "   jjYnNXQewvJvyNNVeyZPSJRazTLAiFXk   "
	reachMaxLengthSpacesBetween := "   jjYnNXQewvJvyN  VeyZPSJRaz  LAiFXk   "

	cases := []struct {
		name     string
		isExpErr bool
	}{
		{"", true},
		{exceedMaxLengthName, true},
		{"Hello-.", true},
		{"Hell O .", true},
		{"Hell O-", true},
		{"Hello%f@k", true},
		{"Hello", false},
		{"Hell-O", false},
		{"Hell O", false},
		{"He.llo Can You Hear Me", false},
		{"Hell'o World", false},
		{reachMaxLengthTrailingSpaces, false},
		{reachMaxLengthSpacesBetween, false},
	}

	for _, c := range cases {
		err := validateLastName(c.name)

		if c.isExpErr {
			assert.EqualError(t, err, errInvalidUserLastName.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestValidateOrganization(t *testing.T) {
	err := validateOrganization("")
	assert.NotNil(t, err)

	err = validateOrganization("abcd")
	assert.Nil(t, err)
}

func TestGenerateUUID(t *testing.T) {
	// test each function call generats unique id's
	uuids := make(map[string]bool)
	for i := 0; i < 30; i++ {
		id, err := generateUUID()
		assert.Nil(t, err)
		assert.NotEqual(t, "", id)

		// test if key exists in the map
		_, ok := uuids[id]
		assert.Equal(t, false, ok)

		uuids[id] = true
	}
}

func TestHashPassword(t *testing.T) {
	// test empty password
	hashed, err := hashPassword("")
	assert.NotNil(t, err)
	assert.EqualError(t, err, errInvalidPassword.Error())
	assert.Equal(t, "", hashed)

	// test passwords with leading and trailing spaces
	hashed, err = hashPassword("    skjfdsd     ")
	assert.NotNil(t, err)
	assert.EqualError(t, err, errInvalidPassword.Error())
	assert.Equal(t, "", hashed)

	// test password and hash password !=
	start := "@#$Sdadf?><;?/`~+-=alskfjwi23xcv"
	for i := 0; i < 30; i++ {
		password := fmt.Sprintf("%s%d", start, i)
		hashed, err := hashPassword(password)
		assert.Nil(t, err)
		assert.NotEqual(t, "", hashed)
		assert.NotEqual(t, password, hashed)
	}
}
