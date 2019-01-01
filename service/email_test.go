package service

import (
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewEmailRequest(t *testing.T) {
	req, err := newEmailRequest(nil, []string{"test"}, "test", "test")
	assert.Nil(t, err)
	assert.NotNil(t, req)

	data := map[string]string{"test": "test"}
	req, err = newEmailRequest(data, nil, "test", "test")
	assert.EqualError(t, err, errEmailRequestFieldsEmpty.Error())
	assert.Nil(t, req)

	req, err = newEmailRequest(data, []string{"test"}, "", "test")
	assert.EqualError(t, err, errEmailRequestFieldsEmpty.Error())
	assert.Nil(t, req)

	req, err = newEmailRequest(data, []string{"test"}, "test", "")
	assert.EqualError(t, err, errEmailRequestFieldsEmpty.Error())
	assert.Nil(t, req)

	req, err = newEmailRequest(data, nil, "", "")
	assert.EqualError(t, err, errEmailRequestFieldsEmpty.Error())
	assert.Nil(t, req)
}

func TestGetAllTemplatePaths(t *testing.T) {
	r := &emailRequest{}

	// empty template
	files, err := r.getAllTemplatePaths("")
	assert.EqualError(t, err, errEmailMainTemplateNotProvided.Error())
	assert.Nil(t, files)
}

func TestParseTemplates(t *testing.T) {
	r := &emailRequest{}

	// test nil
	err := r.parseTemplates(nil)
	assert.EqualError(t, err, errEmailNilFilePaths.Error())

	// wrong file path
	files, err := r.getAllTemplatePaths("wrong_file_name")
	assert.Nil(t, err)
	assert.NotNil(t, files)

	err = r.parseTemplates(files)
	assert.EqualError(t, err, "open ../tmpl/wrong_file_name: no such file or directory")

	// correct file path
	files, err = r.getAllTemplatePaths(templateVerifyEmail)
	assert.Nil(t, err)
	assert.NotNil(t, files)

	err = r.parseTemplates(files)
	assert.Nil(t, err)
}

func TestProcessEmail(t *testing.T) {
	validEmails := []string{
		"hwsc.test+user1@gmail.com",
		"hwsc.test+user2@gmail.com",
		"hwsc.test+user3@gmail.com",
		"hwsc.test+user4@gmail.com",
	}

	mixedValidEmails := []string{
		"hwsc.test+user5@gmail.com",
		"hwsc.test+user6@gmail.com",
		"@@@",
		"hwsc.text+user7@gmail.com",
	}

	cases := []struct {
		emails   []string
		isExpErr bool
		expMsg   string
	}{
		{[]string{"hwsc.test+user0@gmail.com"}, false, ""},
		{validEmails, false, ""},
		{[]string{"123"}, true, ""},
		{mixedValidEmails, true, ""},
	}

	for _, c := range cases {
		r, err := newEmailRequest(nil, c.emails, conf.EmailHost.Username, "HWSC Testing")
		assert.Nil(t, err)
		assert.NotNil(t, r)
		r.body = "Hello World"

		err = r.processEmail()
		if c.isExpErr {
			// gsmtp errors give errors with varying unpredictable id keys
			// ex1: "555 5.5.2 Syntax error. l85sm91728408pfg.161 - gsmtp"
			// ex2: "555 5.5.2 Syntax error. h64sm76201087pfc.142 - gsmtp"
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expMsg, "")
		}
	}
}

func TestSendEmail(t *testing.T) {
	email := []string{"hwsc.test+user0@gmail.com"}
	r, err := newEmailRequest(nil, email, conf.EmailHost.Username, "HWSC Testing")
	assert.Nil(t, err)
	assert.NotNil(t, r)

	// valid
	err = r.sendEmail(templateVerifyEmail)
	assert.Nil(t, err)

	// invalid - empty file
	err = r.sendEmail("")
	assert.EqualError(t, err, errEmailMainTemplateNotProvided.Error())

	// invalid - wrong file name
	err = r.sendEmail("wrong_file")
	assert.EqualError(t, err, "open ../tmpl/wrong_file: no such file or directory")

	// invalid - wrong email
	r.to = []string{"123"}
	err = r.sendEmail(templateVerifyEmail)
	// gsmtp errs includes varying id keys with its msg, cannot test for equalError
	assert.NotNil(t, err)
}
