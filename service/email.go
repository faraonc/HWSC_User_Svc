package service

import (
	"bytes"
	"fmt"
	"github.com/hwsc-org/hwsc-user-svc/conf"
	"io/ioutil"
	"net/smtp"
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
	subjectVerifyEmail  = "Verify account for Humpback whale Social Call"
	templateVerifyEmail = "verify_email.html"
)

func newEmailRequest(data map[string]string, to []string, from string, subject string) (*emailRequest, error) {
	// note, data can be nil
	if to == nil || from == "" || subject == "" {
		return nil, errEmailRequestFieldsEmpty
	}

	return &emailRequest{
		from:         from,
		to:           to,
		subject:      subject,
		templateData: data,
	}, nil
}

func (r *emailRequest) getAllTemplatePaths(mainTemplate string) ([]string, error) {
	if mainTemplate == "" {
		return nil, errEmailMainTemplateNotProvided
	}

	// grab all files in directory
	files, err := ioutil.ReadDir("../tmpl")
	if err != nil {
		return nil, err
	}

	// put files into a string slice
	var allFilePaths []string
	allFilePaths = append(allFilePaths, fmt.Sprintf("../tmpl/%s", mainTemplate))

	for _, file := range files {
		filename := file.Name()
		if strings.HasSuffix(filename, ".tmpl") {
			allFilePaths = append(allFilePaths, fmt.Sprintf("../tmpl/%s", filename))
		}
	}

	return allFilePaths, nil
}

func (r *emailRequest) parseTemplates(filePaths []string) error {
	if filePaths == nil {
		return errEmailNilFilePaths
	}

	templates, err := template.ParseFiles(filePaths...)
	if err != nil {
		return err
	}

	buffer := *new(bytes.Buffer)
	if err := templates.Execute(&buffer, r.templateData); err != nil {
		return err
	}

	r.body = buffer.String()
	return nil
}

func (r *emailRequest) processEmail() error {
	for _, recipient := range r.to {
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n%s\r\n%s",
			r.from, recipient, r.subject, mime, r.body)
		addr := fmt.Sprintf("%s:%s", conf.EmailHost.Host, conf.EmailHost.Port)

		auth := smtp.PlainAuth("", conf.EmailHost.Username, conf.EmailHost.Password, conf.EmailHost.Host)
		err := smtp.SendMail(addr, auth, r.from, []string{recipient}, []byte(msg))
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *emailRequest) sendEmail(mainTemplate string) error {
	if mainTemplate == "" {
		return errEmailMainTemplateNotProvided
	}

	filePaths, err := r.getAllTemplatePaths(mainTemplate)
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
