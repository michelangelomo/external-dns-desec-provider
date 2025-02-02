package main

import (
	"log"
	"os"
)

func loadConfig() Config {
	token := os.Getenv("DESEC_API_TOKEN")
	if token == "" {
		log.Fatal("DESEC_API_TOKEN must be set")
	}
	return Config{APIToken: token}
}
