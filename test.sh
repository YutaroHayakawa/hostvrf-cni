#!/bin/bash

docker build --tag localhost/hostvrf-tester:local ./images/tester

pushd plugins/hostvrf

go build
go test -v -exec sudo

popd
