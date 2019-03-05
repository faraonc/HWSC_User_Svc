package service

import (
	"bytes"
	"fmt"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"github.com/hwsc-org/hwsc-user-svc/consts"
	"io/ioutil"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"text/template"
)

// Request holds transaction email data
type emailRequest struct {
	from         string
	to           []string
	subject      string
	body         string
	templateData map[string]string
}

const (
	// MIME (Multipurpose Internet Mail Extension), extends the format of email
	mime                = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	subjectVerifyEmail  = "Verify email for Humpback Whale Social Call"
	subjectUpdateEmail  = "Verify Request to Update Email"
	templateVerifyEmail = "verify_new_user_email.html"
	templateUpdateEmail = "verify_email_update.html"
	maxEmailLength      = 320

	verificationLinkKey = "VERIFICATION_LINK"
)

var (
	templateDirectory string

	// tests empty string, @ symbol in between, at least 3 chars
	emailRegex = regexp.MustCompile(`.+@.+`)
)

func init() {
	// set template directory
	pwd, _ := os.Getwd()
	templateDirectory = pwd + "/tmpl"
}

// newEmailRequest creates a new emailRequest object, initialized to the parameters passed in
// param "data" is a map that holds dynamic email template data to be interpolated when parsing templates
// param "to" holds the email of the recipient
// param "from" holds the email of the sender
// param "subject" holds the subject of the email
// Returns the initialized emailRequest object or nil if to, from, subject is nil or empty
//
// param "data" can be nil because email templates may contain only static data
func newEmailRequest(data map[string]string, to []string, from string, subject string) (*emailRequest, error) {
	// note, data can be nil
	if data == nil || to == nil || from == "" || subject == "" {
		return nil, consts.ErrEmailRequestFieldsEmpty
	}

	return &emailRequest{
		from:         from,
		to:           to,
		subject:      subject,
		templateData: data,
	}, nil
}

// getAllTemplatePaths walks through the specified directory that holds email templates
// and stores each template path in a slice of strings
// param htmlTemplate is the main html file that references these template files ending in .tmpl
// Returns slice of strings holding all templates

// order matters for future parsing of these files
// the first element in slice must be the html file path that references these .tmpl files
func (r *emailRequest) getAllTemplatePaths(htmlTemplate string) ([]string, error) {
	if htmlTemplate == "" {
		return nil, consts.ErrEmailMainTemplateNotProvided
	}

	// grab all files in directory
	files, err := ioutil.ReadDir(templateDirectory)
	if err != nil {
		return nil, err
	}

	// put files into a string slice
	var allFilePaths []string
	allFilePaths = append(allFilePaths, fmt.Sprintf("%s/%s", templateDirectory, htmlTemplate))

	for _, file := range files {
		filename := file.Name()
		if strings.HasSuffix(filename, ".tmpl") {
			allFilePaths = append(allFilePaths, fmt.Sprintf("%s/%s", templateDirectory, filename))
		}
	}

	return allFilePaths, nil
}

// parseTemplates reads through the files in the slice and generates a new template.
// This template represents the complete template where any .tmpl files referenced in html file
// are interpolated. Afterwards, this parsed template is executed where any variables referenced
// in this template is also interpolated. Finally, this template itself is read and outputted to a buffer
// and this buffer is then converted to a string and stored in property "body" of emailRequest object.
// Returns error if filePaths are nil or any errors generated when parsing/executing
func (r *emailRequest) parseTemplates(filePaths []string) error {
	if filePaths == nil {
		return consts.ErrEmailNilFilePaths
	}

	parsedTemplate, err := template.ParseFiles(filePaths...)
	if err != nil {
		return err
	}

	buffer := &bytes.Buffer{}
	if err := parsedTemplate.Execute(buffer, r.templateData); err != nil {
		return err
	}

	r.body = buffer.String()
	return nil
}

// processEmail preps all necessary email information and sends emails to all recipients
// Returns error if failed to send emails or failed to authenticate

// var "msg" contains the RFC 822-style email with headers (From, To, Subject, MIME)
func (r *emailRequest) processEmail() error {
	for _, recipient := range r.to {
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n%s\r\n%s",
			r.from, recipient, r.subject, mime, r.body)
		addr := fmt.Sprintf("%s:%s", conf.EmailHost.Host, conf.EmailHost.Port)

		auth := smtp.PlainAuth("", conf.EmailHost.Username, conf.EmailHost.Password, conf.EmailHost.Host)
		err := smtp.SendMail(
			addr,
			auth,
			r.from,
			[]string{recipient},
			[]byte(msg))

		if err != nil {
			return err
		}
	}
	return nil
}

// sendEmail is the master function that calls upon sub functions that actually sends the email
// First, template paths need to be grabbed from template directory
// Second, these templates then have to be parsed and interpolated
// Then, with all these information, email is processed and sent
// Returns error if there are any errors returned from the sub functions or if htmlTemplate is empty
func (r *emailRequest) sendEmail(htmlTemplate string) error {
	if htmlTemplate == "" {
		return consts.ErrEmailMainTemplateNotProvided
	}

	filePaths, err := r.getAllTemplatePaths(htmlTemplate)
	if err != nil {
		return err
	}

	if err := r.parseTemplates(filePaths); err != nil {
		return err
	}

	if err := r.processEmail(); err != nil {
		return err
	}

	return nil
}

// validateEmail checks for very basic valid email format and string length
// Returns error if checks fail
func validateEmail(email string) error {
	if len(email) > maxEmailLength || !emailRegex.MatchString(email) {
		return consts.ErrInvalidUserEmail
	}

	return nil
}
