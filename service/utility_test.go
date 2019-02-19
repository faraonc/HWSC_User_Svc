package service

import (
	"fmt"
	pblib "github.com/hwsc-org/hwsc-api-blocks/lib"
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

func TestGenerateSecretExpirationTimestamp(t *testing.T) {
	expirationHour := 3

	// test zero value
	date, err := generateSecretExpirationTimestamp(time.Time{})
	assert.EqualError(t, err, consts.ErrInvalidTimeStamp.Error())
	assert.Nil(t, date)

	// test all days of the week
	currentDate := time.Now()

	// non UTC date
	timeZonedDate := currentDate.UTC()

	cases := []struct {
		date time.Time
	}{
		{currentDate},
		{currentDate.AddDate(0, 0, 1)},
		{currentDate.AddDate(0, 0, 2)},
		{currentDate.AddDate(0, 0, 3)},
		{timeZonedDate.AddDate(0, 0, 4)},
		{timeZonedDate.AddDate(0, 0, 5)},
		{timeZonedDate.AddDate(0, 0, 6)},
	}

	for _, c := range cases {
		expirationDate, err := generateSecretExpirationTimestamp(c.date)
		assert.Nil(t, err)

		if c.date.Location().String() != utc {
			c.date = c.date.UTC()
		}
		assert.Equal(t, (c.date.Weekday()+daysInWeek)%daysInWeek, expirationDate.Weekday())
		assert.Equal(t, expirationHour, expirationDate.Hour())
	}
}
