package service

import (
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDialMongoDB(t *testing.T) {
	// define edge cases to test
	cases := []struct {
		uri      string
		isExpErr bool
		errorStr string
	}{
		{conf.UserDB.Reader, false, ""},
		{conf.UserDB.Writer, false, ""},
		{"", true, "error parsing uri (): scheme must be \"mongodb\" or \"mongodb+srv\""},
		{"mongodb://", true, "error parsing uri (mongodb://): must have at least 1 host"},
	}

	// loop through our edge cases
	// _ is index, we don't use it here, c is per case in cases
	// TODO test context timeouts: https://github.com/hwsc-org/hwsc-user-svc/issues/12
	for _, c := range cases {
		client, err := dialMongoDB(&c.uri)
		if c.isExpErr {
			assert.EqualError(t, err, c.errorStr)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, client)
		}
	}
}

func TestDisconnectMongoClient(t *testing.T) {
	cases := []struct {
		uri        string
		clientType string
		isExpErr   bool
		errorStr   string
	}{
		{conf.UserDB.Reader, reader, false, ""},
		{conf.UserDB.Writer, writer, false, ""},
		{"", "", true, "nil Mongo Client"},
	}

	// TODO test context timeouts: https://github.com/hwsc-org/hwsc-user-svc/issues/12
	for _, c := range cases {
		client, _ := dialMongoDB(&c.uri)
		err := disconnectMongoClient(client, c.clientType)

		if c.isExpErr {
			assert.EqualError(t, err, c.errorStr)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, client)
		}
	}
}

func TestPingMongoClient(t *testing.T) {
	cases := []struct {
		uri      string
		isExpErr bool
		errorStr string
	}{
		{conf.UserDB.Reader, false, ""},
		{conf.UserDB.Writer, false, ""},
		{"", true, "nil Mongo Client"},
	}

	for _, c := range cases {
		client, _ := dialMongoDB(&c.uri)
		err := pingMongoClient(client)

		if c.isExpErr {
			assert.EqualError(t, err, c.errorStr)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, client)
		}
	}

	client, err := dialMongoDB(&conf.UserDB.Reader)
	assert.Nil(t, err)
	err = pingMongoClient(client)
	assert.Nil(t, err)
	err = pingMongoClient(client)
	assert.Nil(t, err)
	err = pingMongoClient(client)
	assert.Nil(t, err)
	err = pingMongoClient(client)
	assert.Nil(t, err)
}
