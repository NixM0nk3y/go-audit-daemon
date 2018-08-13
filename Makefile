bin:
	govendor sync
	go build

.PHONY: bin
.DEFAULT_GOAL := bin
