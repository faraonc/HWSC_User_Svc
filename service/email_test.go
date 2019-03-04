package service

import (
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewEmailRequest(t *testing.T) {
	testData := map[string]string{"random": "data"}

	desc := "test valid fields"
	req, err := newEmailRequest(testData, []string{"test"}, "test", "test")
	assert.Nil(t, err, desc)
	assert.NotNil(t, req, desc)

	desc = "test nil data"
	req, err = newEmailRequest(nil, []string{"test"}, "test", "test")
	assert.EqualError(t, err, consts.ErrEmailRequestFieldsEmpty.Error(), desc)
	assert.Nil(t, req, desc)

	desc = "test empty to parameter"
	req, err = newEmailRequest(testData, nil, "test", "test")
	assert.EqualError(t, err, consts.ErrEmailRequestFieldsEmpty.Error(), desc)
	assert.Nil(t, req, desc)

	desc = "test empty from parameter"
	req, err = newEmailRequest(testData, []string{"test"}, "", "test")
	assert.EqualError(t, err, consts.ErrEmailRequestFieldsEmpty.Error(), desc)
	assert.Nil(t, req, desc)

	desc = "test empty subject parameter"
	req, err = newEmailRequest(testData, []string{"test"}, "test", "")
	assert.EqualError(t, err, consts.ErrEmailRequestFieldsEmpty.Error(), desc)
	assert.Nil(t, req, desc)

	desc = "test multiple nil and empty values"
	req, err = newEmailRequest(testData, nil, "", "")
	assert.EqualError(t, err, consts.ErrEmailRequestFieldsEmpty.Error(), desc)
	assert.Nil(t, req, desc)
}

func TestGetAllTemplatePaths(t *testing.T) {
	r := &emailRequest{}

	// empty template
	files, err := r.getAllTemplatePaths("")
	assert.EqualError(t, err, consts.ErrEmailMainTemplateNotProvided.Error())
	assert.Nil(t, files)
}

func TestParseTemplates(t *testing.T) {
	r := &emailRequest{}

	// test nil
	err := r.parseTemplates(nil)
	assert.EqualError(t, err, consts.ErrEmailNilFilePaths.Error())

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
	}

	mixedValidEmails := []string{
		"hwsc.test+user5@gmail.com",
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

	testData := map[string]string {verificationLinkKey: "Unit Testing Process Email"}
	for _, c := range cases {
		r, err := newEmailRequest(testData, c.emails, conf.EmailHost.Username, "HWSC Testing")
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
	testData := map[string]string { verificationLinkKey: "Unit Testing sendEmail"}
	email := []string{"hwsc.test+user0@gmail.com"}
	r, err := newEmailRequest(testData, email, conf.EmailHost.Username, "HWSC Testing")
	assert.Nil(t, err)
	assert.NotNil(t, r)

	// valid
	err = r.sendEmail(templateVerifyEmail)
	assert.Nil(t, err)

	// invalid - empty file
	err = r.sendEmail("")
	assert.EqualError(t, err, consts.ErrEmailMainTemplateNotProvided.Error())

	// invalid - wrong file name
	err = r.sendEmail("wrong_file")
	assert.EqualError(t, err, "open ../tmpl/wrong_file: no such file or directory")

	// invalid - wrong email
	r.to = []string{"123"}
	err = r.sendEmail(templateVerifyEmail)
	// gsmtp errs includes varying id keys with its msg, cannot test for equalError
	assert.NotNil(t, err)
}

func TestValidateEmail(t *testing.T) {
	exceedMaxLengthEmail := ")YFTcgcK}6?J&1%{c0OV7@)N4v^BLXcZH9eQ9kl5V_y>" +
		"5vnonsB0cA(h@ZD+a$Ny3D6K@EhGx}mJ*<%MZ|7f@2u@)xclP_n(Q|}+ZK58m*0VU^" +
		"Qq}!m(Wper^@72*|GyZDt?u30Y5KiEOE@Hwm#q?2ot9IsOer(yZ}hUbL@}&1TX1+_" +
		"<tZVl^JbBAL0kzUgk789O_e}5vEZeA&8S:5A:NhED1Ae*y9xXt^!<TU7:n8nK#A$wB" +
		">Wpzo|iZt#l0T:e4n??hd>CBjCnITEakpi@W{>1B06|D@<$#R&&11)W2IHM3D(|@" +
		"b?FrdG&t:7aF4#W}"

	cases := []struct {
		email     string
		isExpErr  bool
		expErrMsg string
	}{
		{"", true, consts.ErrInvalidUserEmail.Error()},
		{"a", true, consts.ErrInvalidUserEmail.Error()},
		{"ab", true, consts.ErrInvalidUserEmail.Error()},
		{"abc", true, consts.ErrInvalidUserEmail.Error()},
		{"@bc", true, consts.ErrInvalidUserEmail.Error()},
		{"ab@", true, consts.ErrInvalidUserEmail.Error()},
		{"@", true, consts.ErrInvalidUserEmail.Error()},
		{"a@", true, consts.ErrInvalidUserEmail.Error()},
		{"@a", true, consts.ErrInvalidUserEmail.Error()},
		{exceedMaxLengthEmail, true, consts.ErrInvalidUserEmail.Error()},
		{"@@@", false, ""},
		{"!@@", false, ""},
		{"@@#", false, ""},
		{"lisakeem@outlook.com", false, ""},
	}

	// TODO test for non-existing emails
	for _, c := range cases {
		err := validateEmail(c.email)

		if c.isExpErr {
			assert.EqualError(t, err, c.expErrMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}
