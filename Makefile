bin:
	govendor sync
	go build

test:
	govendor sync
	go test -v

.PHONY: bin
.DEFAULT_GOAL := bin
