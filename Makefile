SHELL := /bin/bash

make krain:
	source cmd/krain-sec/.env && reflex -r '\.go' -s -- sh -c 'go run cmd/krain-sec/main.go'