# Build stage
FROM golang:1.24.2-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o webhook cmd/webhook.go

# Final stage
FROM alpine:3.18

ARG USER=1000
RUN adduser -D $USER
USER $USER

WORKDIR /app
COPY --from=builder /app/webhook .
EXPOSE 8888
CMD ["./webhook"]