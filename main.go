package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := loadConfig()
	r := gin.Default()

	r.GET("/records", handleGetRecords(cfg))
	r.POST("/records", handlePostRecords(cfg))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
