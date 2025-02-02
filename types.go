package main

import "time"

var (
	desecAPIBase   = "https://desec.io/api/v1" // changed from constant to variable
	defaultTTL     = 300
	workerCount    = 5
	requestTimeout = 10 * time.Second
)

type Config struct {
	APIToken string
}

type Record struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Targets []string `json:"targets"`
}

type Change struct {
	Action string `json:"action"`
	Record Record `json:"record"`
}

type RRSet struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

type ErrorResponse struct {
	Error string `json:"error,omitempty"`
}

type SuccessResponse struct {
	Success bool `json:"success"`
}
