# Multi-stage build for minimal production image
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o authpin ./cmd/authpin

FROM alpine:3.24
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/authpin /app/authpin
COPY config.example.yaml /app/config.yaml

EXPOSE 8080
ENTRYPOINT ["/app/authpin", "-config", "/app/config.yaml"]
