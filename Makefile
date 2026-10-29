.PHONY: build test test-coverage fmt lint clean docker-build docker-build-multiarch

build:
	@go build -o bin/authpin ./cmd/authpin

test:
	@go test -v ./...

test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

fmt:
	@go fmt ./...

lint:
	@which golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed, skipping"

clean:
	@rm -rf bin/ coverage.out coverage.html

docker-build:
	@docker build -t authpin:latest .

docker-build-multiarch:
	@docker buildx build --platform linux/amd64,linux/arm64 -t authpin:latest .
