package service

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"text/template"
)

type transactionEmail interface {
}

// Request holds transaction email data
type requestData struct {
	from    string
	to      string
	subject string
	body    string
}

const (
	// MIME (Multipurpose Internet Mail Extension), extends the format of email
	mime = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

func getAllTemplatePaths(mainTemplate string) ([]string, error) {
	if mainTemplate == "" {
		return nil, errEmailMainTemplateNotProvided
	}

	// grab all files in directory
	files, err := ioutil.ReadDir("../tmpl/inc")
	if err != nil {
		return nil, err
	}

	// put files into a string slice
	var allFilePaths []string
	allFilePaths = append(allFilePaths, fmt.Sprintf("../tmpl/%s", mainTemplate))

	for _, file := range files {
		filename := file.Name()
		if strings.HasSuffix(filename, ".tmpl") {
			allFilePaths = append(allFilePaths, fmt.Sprintf("./tmpl/inc/%s", filename))
		}
	}

	return allFilePaths, nil
}

func parseTemplates(filePaths []string, templateData map[string]string) (*bytes.Buffer, error) {
	templates, err := template.ParseFiles(filePaths...)
	if err != nil {
		return nil, err
	}

	buffer := *new(bytes.Buffer)
	if err := templates.Execute(&buffer, templateData); err != nil {
		return nil, err
	}

	return &buffer, nil
}

func sendEmail(mainTemplate string, templateData map[string]string) {

}
