package desec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const defaultBaseURL = "https://desec.io/api/v1"

// RRSet represents a DNS resource record set in the deSEC API.
type RRSet struct {
	SubName string   `json:"subname"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
	TTL     int      `json:"ttl"`
}

// RateLimitError is returned when the deSEC API responds with 429 Too Many Requests.
type RateLimitError struct {
	RetryAfter int // seconds until the rate limit resets
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("deSEC API rate limit exceeded, retry after %d seconds", e.RetryAfter)
}

// APIError is returned for non-2xx, non-429 responses from the deSEC API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("deSEC API error: status %d, body: %s", e.StatusCode, e.Body)
}

// Client is a minimal deSEC API client.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient creates a new deSEC API client.
func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{},
		baseURL:    defaultBaseURL,
		token:      token,
	}
}

// GetRecords retrieves all RRSets for a domain.
func (c *Client) GetRecords(ctx context.Context, domain string) ([]RRSet, error) {
	url := fmt.Sprintf("%s/domains/%s/rrsets/", c.baseURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var rrsets []RRSet
	if err := c.do(req, &rrsets); err != nil {
		return nil, err
	}
	return rrsets, nil
}

// BulkCreateRecords creates multiple RRSets for a domain.
func (c *Client) BulkCreateRecords(ctx context.Context, domain string, rrsets []RRSet) ([]RRSet, error) {
	url := fmt.Sprintf("%s/domains/%s/rrsets/", c.baseURL, domain)

	body, err := json.Marshal(rrsets)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var result []RRSet
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BulkUpdateRecords updates multiple RRSets for a domain using PUT (full replacement).
func (c *Client) BulkUpdateRecords(ctx context.Context, domain string, rrsets []RRSet) ([]RRSet, error) {
	url := fmt.Sprintf("%s/domains/%s/rrsets/", c.baseURL, domain)

	body, err := json.Marshal(rrsets)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var result []RRSet
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BulkDeleteRecords deletes RRSets by updating them with empty Records fields.
func (c *Client) BulkDeleteRecords(ctx context.Context, domain string, rrsets []RRSet) error {
	toDelete := make([]RRSet, len(rrsets))
	for i, rr := range rrsets {
		toDelete[i] = RRSet{
			SubName: rr.SubName,
			Type:    rr.Type,
			Records: []string{},
			TTL:     rr.TTL,
		}
	}
	_, err := c.BulkUpdateRecords(ctx, domain, toDelete)
	return err
}

// do executes an HTTP request and handles response parsing.
func (c *Client) do(req *http.Request, result any) error {
	req.Header.Set("Authorization", "Token "+c.token)
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := 0
		if v := resp.Header.Get("Retry-After"); v != "" {
			retryAfter, _ = strconv.Atoi(v)
		}
		return &RateLimitError{RetryAfter: retryAfter}
	}

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(bodyBytes),
		}
	}

	// For 204 No Content or when no result is expected
	if result == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(result)
}
