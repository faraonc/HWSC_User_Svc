package service

import (
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
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

func TestGenerateEmailToken(t *testing.T) {
	cases := []struct {
		uuid       string
		permission string
		isExpError bool
		expError   error
	}{
		{"", "", true, authconst.ErrInvalidUUID},
		{"01d1na5ekzr7p98hragv5fmvx", "", true, authconst.ErrInvalidUUID},
		{"01d3x3wm2nnrdfzp0tka2vw9dx", "", true, authconst.ErrInvalidPermission},
		{"01d3x3wm2nnrdfzp0tka2vw9dx", "SuperAdmin", true, authconst.ErrInvalidPermission},
		{"01d3x3wm2nnrdfzp0tka2vw9dx", "USER", false, nil},
	}
	for _, c := range cases {
		id, err := generateEmailToken(c.uuid, c.permission)
		if c.isExpError {
			assert.EqualError(t, err, c.expError.Error())
		} else {
			assert.NotNil(t, id)
		}
	}
}

func TestGenerateSecretKey(t *testing.T) {
	// NOTE: unable to force a race condition given the nature of randomByte used in generateEmailToken()
	// but functionality is same as generateUUID and that's been tested for race conditions

	// test for invalid token byte size
	token, err := generateSecretKey(0)
	assert.EqualError(t, err, consts.ErrInvalidTokenSize.Error())
	assert.Equal(t, "", token)

	token, err = generateSecretKey(-256)
	assert.EqualError(t, err, consts.ErrInvalidTokenSize.Error())
	assert.Equal(t, "", token)

	// test race condition
	const count = 100
	var tokens sync.Map
	var wg sync.WaitGroup

	wg.Add(count)
	start := make(chan struct{})

	for i := 0; i < count; i++ {
		go func() {
			<-start
			defer wg.Done()

			// store tokens in map to check for duplicates
			token, err := generateSecretKey(emailTokenByteSize)
			assert.Nil(t, err)
			assert.NotEqual(t, "", token)

			_, ok := tokens.Load(token)
			assert.Equal(t, false, ok)

			tokens.Store(token, true)
		}()
	}

	close(start)
	wg.Wait()
}

func TestGenerateExpirationTimestamp(t *testing.T) {
	desc := "test zero value for time"
	date, err := generateExpirationTimestamp(time.Time{}, 0)
	assert.EqualError(t, err, consts.ErrInvalidTimeStamp.Error(), desc)
	assert.Nil(t, date, desc)

	desc = "test zero number of days"
	date, err = generateExpirationTimestamp(time.Now(), 0)
	assert.EqualError(t, err, consts.ErrInvalidNumberOfDays.Error(), desc)
	assert.Nil(t, date, desc)

	desc = "test negative number of days"
	date, err = generateExpirationTimestamp(time.Now(), -5)
	assert.EqualError(t, err, consts.ErrInvalidNumberOfDays.Error(), desc)
	assert.Nil(t, date, desc)

	desc7days := "test adding 7 days to current date to various days of the week"
	desc14days := "test adding 14 days to current date to various days of the week"
	currentDate := time.Now()

	// non UTC date
	timeZonedDate := currentDate.UTC()
	expirationHour := 3

	cases := []struct {
		date    time.Time
		addDays time.Weekday
	}{
		{currentDate, daysInOneWeek},
		{currentDate.AddDate(0, 0, 1), daysInOneWeek},
		{currentDate.AddDate(0, 0, 2), daysInOneWeek},
		{currentDate.AddDate(0, 0, 3), daysInOneWeek},
		{timeZonedDate.AddDate(0, 0, 4), daysInOneWeek},
		{timeZonedDate.AddDate(0, 0, 5), daysInOneWeek},
		{timeZonedDate.AddDate(0, 0, 6), daysInOneWeek},
		{currentDate, daysInTwoWeeks},
		{currentDate.AddDate(0, 0, 1), daysInTwoWeeks},
		{currentDate.AddDate(0, 0, 2), daysInTwoWeeks},
		{currentDate.AddDate(0, 0, 3), daysInTwoWeeks},
		{timeZonedDate.AddDate(0, 0, 4), daysInTwoWeeks},
		{timeZonedDate.AddDate(0, 0, 5), daysInTwoWeeks},
		{timeZonedDate.AddDate(0, 0, 6), daysInTwoWeeks},
	}

	for _, c := range cases {
		expirationDate, err := generateExpirationTimestamp(c.date, int(c.addDays))

		if c.date.Location().String() != utc {
			c.date = c.date.UTC()
		}

		if c.addDays == daysInOneWeek {
			desc = desc7days
		} else {
			desc = desc14days
		}

		assert.Nil(t, err, desc)
		assert.Equal(t, (c.date.Weekday()+c.addDays)%c.addDays, expirationDate.Weekday(), desc)
		assert.Equal(t, expirationHour, expirationDate.Hour(), desc)
	}
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
		ExpirationTimestamp: time.Now().Unix(),
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
