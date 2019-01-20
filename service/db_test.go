package service

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRefreshDBConnection(t *testing.T) {
	assert.NotNil(t, postgresDB)

	//verify connection on supposedly opened connection
	err := refreshDBConnection()
	assert.Nil(t, err)
	assert.NotNil(t, postgresDB)

	// close connection
	err = postgresDB.Close()
	assert.Nil(t, err)

	// test on closed connection
	err = refreshDBConnection()
	assert.NotNil(t, err)
	assert.Nil(t, postgresDB)

	//verify initializing
	err = refreshDBConnection()
	assert.Nil(t, err)
}

//TODO test db utility functions
