# Build stage
FROM golang:1.24.2-alpine AS builder

ARG VERSION="v0.0.0-dev"

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X 'main.Version=${VERSION}'" -o webhook cmd/webhook.go

# Final stage
FROM alpine:3.21

ARG USER=1000
RUN adduser -D $USER
USER $USER

WORKDIR /app
COPY --from=builder /app/webhook .
EXPOSE 8888
CMD ["./webhook"]