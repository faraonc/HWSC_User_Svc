#!/bin/bash
go test -coverprofile=coverage.out -failfast -race

# Opens a summary of code coverage in the browser
go tool cover -html=coverage.out
