package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func getSubnameAndDomain(fullName string) (string, string) {
	fullName = strings.TrimSuffix(fullName, ".")
	parts := strings.Split(fullName, ".")
	if len(parts) < 2 {
		return "", fullName
	}
	return strings.Join(parts[:len(parts)-2], "."), parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func processChange(cfg Config, change Change) interface{} {
	if change.Action == "" || change.Record.Name == "" {
		return ErrorResponse{"Invalid change request"}
	}

	subname, domain := getSubnameAndDomain(change.Record.Name)
	rrType := strings.ToUpper(change.Record.Type)
	ttl := change.Record.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	client := &http.Client{Timeout: requestTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/domains/%s/rrsets/%s/%s/", desecAPIBase, domain, subname, rrType)

	switch change.Action {
	case "CREATE", "UPDATE":
		return createOrUpdateRRSet(client, ctx, url, cfg.APIToken, ttl, change.Record.Targets)
	case "DELETE":
		return deleteRRSet(client, ctx, url, cfg.APIToken, change.Record.Targets)
	default:
		return ErrorResponse{fmt.Sprintf("Unsupported action: %s", change.Action)}
	}
}

func createOrUpdateRRSet(client *http.Client, ctx context.Context, url, token string, ttl int, targets []string) interface{} {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Token "+token)

	resp, err := client.Do(req)
	if err != nil {
		return ErrorResponse{err.Error()}
	}
	defer resp.Body.Close()

	var existing *RRSet
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
			return ErrorResponse{err.Error()}
		}
	}

	unique := make(map[string]struct{})
	if existing != nil {
		for _, record := range existing.Records {
			unique[record] = struct{}{}
		}
	}
	for _, target := range targets {
		unique[target] = struct{}{}
	}

	merged := make([]string, 0, len(unique))
	for target := range unique {
		merged = append(merged, target)
	}

	data := RRSet{
		Records: merged,
		TTL:     ttl,
	}
	jsonData, _ := json.Marshal(data)

	if existing != nil {
		req, _ = http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(jsonData))
	} else {
		req, _ = http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(url, "/")+"/", bytes.NewReader(jsonData))
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return ErrorResponse{err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return ErrorResponse{fmt.Sprintf("API error: %d", resp.StatusCode)}
	}
	return SuccessResponse{true}
}

func deleteRRSet(client *http.Client, ctx context.Context, url, token string, targets []string) interface{} {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Token "+token)

	resp, err := client.Do(req)
	if err != nil {
		return ErrorResponse{err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return SuccessResponse{true}
	}

	if resp.StatusCode != http.StatusOK {
		return ErrorResponse{fmt.Sprintf("API error: %d", resp.StatusCode)}
	}

	var existing RRSet
	if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
		return ErrorResponse{err.Error()}
	}

	remaining := make([]string, 0)
	targetSet := make(map[string]struct{})
	for _, t := range targets {
		targetSet[t] = struct{}{}
	}
	for _, record := range existing.Records {
		if _, found := targetSet[record]; !found {
			remaining = append(remaining, record)
		}
	}

	if len(remaining) > 0 {
		data := RRSet{
			Records: remaining,
			TTL:     existing.TTL,
		}
		jsonData, _ := json.Marshal(data)
		req, _ = http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequestWithContext(ctx, "DELETE", url, nil)
	}
	req.Header.Set("Authorization", "Token "+token)

	resp, err = client.Do(req)
	if err != nil {
		return ErrorResponse{err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return ErrorResponse{fmt.Sprintf("API error: %d", resp.StatusCode)}
	}
	return SuccessResponse{true}
}
