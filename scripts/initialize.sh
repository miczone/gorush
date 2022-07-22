#!/usr/bin/bash

go mod init github.com/wokaio/gorush
go mod tidy
go mod vendor
go mod verify
go mod vendor