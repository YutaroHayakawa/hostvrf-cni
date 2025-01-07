#!/bin/sh

docker build --tag localhost/hostvrf-tester:local .

go build -o hostvrf

go test -v -exec sudo
