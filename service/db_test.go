package service

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRefreshDBConnection(t *testing.T) {
	assert.NotNil(t, postgresDB)

	//verify connection on supposedly opened connection
	response := refreshDBConnection()
	assert.Nil(t, response)

	// close connection
	err := postgresDB.Close()
	assert.Nil(t, err)

	// test on closed connection
	response = refreshDBConnection()
	assert.NotNil(t, response)

	// test null
	postgresDB = nil

	//verify initializing
	response = refreshDBConnection()
	assert.Nil(t, response)
}
