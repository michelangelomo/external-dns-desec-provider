package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

func handleGetRecords(cfg Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		zone := strings.TrimSuffix(ctx.Query("zone"), ".")
		if zone == "" {
			ctx.JSON(http.StatusBadRequest, ErrorResponse{"Missing zone parameter"})
			return
		}

		client := &http.Client{Timeout: requestTimeout}
		url := fmt.Sprintf("%s/domains/%s/rrsets/", desecAPIBase, zone)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Token "+cfg.APIToken)

		resp, err := client.Do(req)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, ErrorResponse{err.Error()})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			ctx.JSON(resp.StatusCode, ErrorResponse{fmt.Sprintf("DESEC API error: %d", resp.StatusCode)})
			return
		}

		var rrsets []RRSet
		if err := json.NewDecoder(resp.Body).Decode(&rrsets); err != nil {
			ctx.JSON(http.StatusInternalServerError, ErrorResponse{err.Error()})
			return
		}

		records := make([]Record, 0)
		for _, rrset := range rrsets {
			name := zone
			if rrset.Subname != "" {
				name = fmt.Sprintf("%s.%s", rrset.Subname, zone)
			}
			for _, target := range rrset.Records {
				records = append(records, Record{
					Name:    name,
					Type:    rrset.Type,
					TTL:     rrset.TTL,
					Targets: []string{target},
				})
			}
		}

		ctx.JSON(http.StatusOK, records)
	}
}

func handlePostRecords(cfg Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var changes []Change
		if err := ctx.ShouldBindJSON(&changes); err != nil {
			ctx.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
			return
		}

		results := make([]interface{}, len(changes))
		workChan := make(chan int, len(changes))
		var wg sync.WaitGroup
		var mu sync.Mutex

		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for index := range workChan {
					result := processChange(cfg, changes[index])
					mu.Lock()
					results[index] = result
					mu.Unlock()
				}
			}()
		}

		for i := range changes {
			workChan <- i
		}
		close(workChan)
		wg.Wait()

		status := http.StatusOK
		for _, res := range results {
			if _, ok := res.(ErrorResponse); ok {
				status = http.StatusMultiStatus
				break
			}
		}

		ctx.JSON(status, gin.H{"results": results})
	}
}
