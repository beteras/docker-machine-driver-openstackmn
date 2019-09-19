BIN = bin/docker-machine-driver-openstackmn

.DEFAULT_GOAL := ${BIN}

${BIN}: *.go bin/*.go
	@# GOGC=off CGOENABLED=0 ???
	go build -i -o $@ ./bin
	strip $@

.PHONY: install
install:
	@# TODO: How to install binary built in $GOPATH directly from "go" command ?
	cp ${BIN} $$GOPATH/bin
