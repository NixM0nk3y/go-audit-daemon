// +build linux

package main

import (
	"os"
        "log"
)

var l = log.New(os.Stdout, "", 0)
var el = log.New(os.Stderr, "", 0)

func main() {
    el.Println("Starting go-audit-daemon")
}
