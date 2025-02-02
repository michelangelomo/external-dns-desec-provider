# Build stage
FROM golang:1.23.4-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o webhook .

# Final stage
FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/webhook .
EXPOSE 8080
CMD ["./webhook"]