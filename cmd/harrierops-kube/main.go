package main

import (
	"os"

	"harrierops-kube/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, os.Environ()))
}
