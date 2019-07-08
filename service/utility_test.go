package service

import (
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/auth"
	authconst "github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

func TestIsStateAvailable(t *testing.T) {
	// NOTE: force a race condition by commenting out the locks inside isStateAvailable()

	// test for unavailability
	serviceStateLocker.currentServiceState = unavailable
	assert.Equal(t, unavailable, serviceStateLocker.currentServiceState)

	ok := serviceStateLocker.isStateAvailable()
	assert.Equal(t, false, ok)

	// test for availability
	serviceStateLocker.currentServiceState = available
	assert.Equal(t, available, serviceStateLocker.currentServiceState)

	ok = serviceStateLocker.isStateAvailable()
	assert.Equal(t, true, ok)

	// test race conditions
	const count = 20
	var wg sync.WaitGroup
	start := make(chan struct{}) // signal channel

	wg.Add(count) // #count go routines to wait for

	for i := 0; i < count; i++ {
		go func() {
			<-start // blocks code below, until channel is closed

			defer wg.Done()
			_ = serviceStateLocker.isStateAvailable()
		}()
	}

	close(start) // starts executing blocked goroutines almost at the same time

	// test that read-lock inside isStateAvailable() blocks this write-lock
	serviceStateLocker.lock.Lock()
	serviceStateLocker.currentServiceState = available
	serviceStateLocker.lock.Unlock()

	wg.Wait() // wait until all goroutines finish executing
}

func TestValidateUser(t *testing.T) {
	// valid
	validTest := pblib.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid first name
	invalidFirstName := pblib.User{
		FirstName:    "",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid last name
	invalidLastName := pblib.User{
		FirstName:    "Lisa",
		LastName:     "",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid email
	invalidEmail := pblib.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "@",
		Password:     "12345678",
		Organization: "uwb",
	}

	// invalid password
	invalidPassword := pblib.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "",
		Organization: "uwb",
	}

	// invalid organization
	invalidOrg := pblib.User{
		FirstName:    "Lisa",
		LastName:     "Kim",
		Email:        "lisa@test.com",
		Password:     "12345678",
		Organization: "",
	}

	cases := []struct {
		user     *pblib.User
		isExpErr bool
		expMsg   string
	}{
		{&validTest, false, ""},
		{&invalidFirstName, true, consts.ErrInvalidUserFirstName.Error()},
		{&invalidLastName, true, consts.ErrInvalidUserLastName.Error()},
		{&invalidEmail, true, consts.ErrInvalidUserEmail.Error()},
		{&invalidPassword, true, consts.ErrInvalidPassword.Error()},
		{&invalidOrg, true, consts.ErrInvalidUserOrganization.Error()},
		{nil, true, consts.ErrNilRequestUser.Error()},
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

func TestValidatePassword(t *testing.T) {
	err := validatePassword("")
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())

	err = validatePassword("                 ")
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())

	err = validatePassword("1234l2k3jalkj;skdfj")
	assert.Nil(t, err)
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
			assert.EqualError(t, err, consts.ErrInvalidUserFirstName.Error())
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
			assert.EqualError(t, err, consts.ErrInvalidUserLastName.Error())
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
	// NOTE: force a race condition by commenting out the locks inside generateUUID()

	const count = 100
	var tokens sync.Map

	var wg sync.WaitGroup // waits until all goroutines finish before executing code below wg.Wait()
	wg.Add(count)         // indicate we are going to wait for 100 go routines

	// start is a signal channel
	// channel of empty structs is used to indicate that this channel
	// will only be used for signalling and not for passing data
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		go func() {
			// <-start blocks code below, waiting until the for loop is finished
			// it waits for the start channel to be closed,
			// once closed, all goroutines will execute(start) almost simultaneously
			<-start

			// decrement wg.Add, indicates 1 go routine has finished
			// defer will call wg.Done() at end of go routine
			defer wg.Done()

			// store tokens in map to check for duplicates
			uuid, err := generateUUID()
			assert.Nil(t, err)
			assert.NotEqual(t, "", uuid)

			_, ok := tokens.Load(uuid)
			assert.Equal(t, false, ok)

			tokens.Store(uuid, true)
		}()
	}

	// closing this channel, will unblock it,
	// allowing execution to continue
	close(start)

	// wait for all 100 go routines to finish (when wg.Add reaches 0)
	// blocks from running any code below it
	wg.Wait()
}

func TestHashPassword(t *testing.T) {
	// test empty password
	hashed, err := hashPassword("")
	assert.NotNil(t, err)
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())
	assert.Equal(t, "", hashed)

	// test passwords with leading and trailing spaces
	hashed, err = hashPassword("    skjfdsd     ")
	assert.NotNil(t, err)
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())
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

func TestComparePassword(t *testing.T) {
	pass1 := "lakjsdfkj2#flskjf#24133132asdf][askj2@34242dskafjASDF"
	pass2 := "123432535lkjdlkfaj"

	pass1Hashed, err := hashPassword(pass1)
	assert.Nil(t, err)

	err = comparePassword(pass1Hashed, pass1)
	assert.Nil(t, err)

	err = comparePassword(pass1Hashed, pass2)
	assert.EqualError(t, err, "crypto/bcrypt: hashedPassword is not the hash of the given password")

	err = comparePassword("", pass2)
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())

	err = comparePassword(pass1Hashed, "")
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())

	err = comparePassword("", "")
	assert.EqualError(t, err, consts.ErrInvalidPassword.Error())
}

func TestSetCurrentSecretOnce(t *testing.T) {
	err := unitTestDeleteAuthSecretTable()
	assert.Nil(t, err)

	desc := "test no active key in db error"
	err = setCurrentSecretOnce()
	assert.EqualError(t, err, consts.ErrNoActiveSecretKeyFound.Error(), desc)

	desc = "test nil return when currAuthSecret is already set"
	currAuthSecret = &pblib.Secret{
		Key:                 "alksjdklasdjf",
		CreatedTimestamp:    time.Now().Unix(),
		ExpirationTimestamp: time.Now().Unix(), // TODO fix expiration in 1 week
	}
	err = setCurrentSecretOnce()
	assert.Nil(t, err, desc)

	desc = "test retrieval and setting of an existing active key in db"
	currAuthSecret = nil
	err = insertNewAuthSecret()
	assert.Nil(t, err)
	err = setCurrentSecretOnce()
	assert.Nil(t, err, desc)
	retrievedSecret, err := getActiveSecretRow()
	assert.Nil(t, err)
	assert.Equal(t, currAuthSecret.GetKey(), retrievedSecret.GetKey())
}

func TestGenerateEmailVerifyLink(t *testing.T) {
	desc := "test empty string"
	link, err := generateEmailVerifyLink("")
	assert.Empty(t, link, desc)
	assert.EqualError(t, err, authconst.ErrEmptyToken.Error(), desc)

	desc = "test valid token"
	token := "someRandomTokenString123"
	manuallyBuiltLink := fmt.Sprintf("%s/%s=%s", domainName, verifyEmailLinkStub, token)
	link, err = generateEmailVerifyLink(token)
	assert.Equal(t, manuallyBuiltLink, link, desc)
	assert.Nil(t, err, desc)
}

func TestGetAuthIdentification(t *testing.T) {
	lastName1 := "GetToken-One"
	lastName2 := "GetToken-Two"

	// refresh secret table
	retrievedSecret, err := unitTestDeleteInsertGetAuthSecret()
	assert.Nil(t, err)
	assert.NotNil(t, retrievedSecret)
	currAuthSecret = retrievedSecret

	// insert a user
	responseUser1, err := unitTestInsertUser(lastName1)
	assert.Nil(t, err)
	assert.NotEmpty(t, responseUser1)
	responseUser1.GetUser().Password = lastName1

	// insert another user to test setting of nil currAuthSecret
	responseUser2, err := unitTestInsertUser(lastName2)
	assert.Nil(t, err)
	assert.NotEmpty(t, responseUser2)
	responseUser2.GetUser().Password = lastName2

	cases := []struct {
		user     *pblib.User
		isExpErr bool
		expMsg   string
	}{
		// valid
		{responseUser1.GetUser(), false, ""},
		{responseUser2.GetUser(), false, ""},
		// nil user object
		{nil, true, consts.ErrStatusNilRequestUser.Error()},
	}
	for _, c := range cases {
		identification, err := getAuthIdentification(c.user)

		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg)
			assert.Nil(t, identification)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, identification)
		}
	}
}

func TestNewAuthIdentification(t *testing.T) {
	err := insertNewAuthSecret()
	assert.Nil(t, err, "generate auth secret")
	err = setCurrentSecretOnce()
	assert.Nil(t, err, "set auth secret")
	cases := []struct {
		desc     string
		header   *auth.Header
		body     *auth.Body
		isExpErr bool
		expMsg   string
	}{
		{"test nil header", nil, validAuthTokenBody, true, authconst.ErrNilHeader.Error()},
		{"test nil body", validAuthTokenHeader, nil, true, authconst.ErrNilBody.Error()},
		{"test for valid input", validAuthTokenHeader, validAuthTokenBody, false, ""},
	}
	for _, c := range cases {
		identification, err := newAuthIdentification(c.header, c.body)
		if c.isExpErr {
			assert.EqualError(t, err, c.expMsg, c.desc)
			assert.Nil(t, identification, c.desc)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, identification, c.desc)
		}
	}

	// sleep is needed to ensure expiration timestamps are different
	time.Sleep(2 * time.Second)
	caseNewAuthToken := "test to generate new auth token"
	validID1, err := newAuthIdentification(validAuthTokenHeader, validAuthTokenBody)
	assert.NotNil(t, validID1, caseNewAuthToken)
	assert.Nil(t, err, caseNewAuthToken)
	time.Sleep(2 * time.Second)
	validID2, err := newAuthIdentification(validAuthTokenHeader, validAuthTokenBody)
	assert.NotNil(t, validID1, caseNewAuthToken)
	assert.Nil(t, err, caseNewAuthToken)

	// ensure the old auth token is different with the new auth token
	assert.NotEqual(t, validID1.Token, validID2.Token, caseNewAuthToken)

	// ensure we get the new auth token and not the old auth token
	retrievedToken, err := getAuthTokenRow(validAuthTokenBody.UUID)
	assert.Nil(t, err, caseNewAuthToken)
	assert.Equal(t, validID2.Token, retrievedToken.token, caseNewAuthToken)

	caseNewAuthSecret := "test new auth secret"
	err = insertNewAuthSecret()
	assert.Nil(t, err, caseNewAuthSecret)
	retrievedToken, err = getAuthTokenRow(validAuthTokenBody.UUID)
	assert.Nil(t, err, caseNewAuthSecret)
	assert.Equal(t, validID2.Token, retrievedToken.token, caseNewAuthSecret)
}
