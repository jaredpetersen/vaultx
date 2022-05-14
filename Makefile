all: test build
install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/vektra/mockery/v2@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
build:
	go build
format:
	goimports -local "github.com/jaredpetersen/vaultx" -w .
	gofmt -w -s .
check:
	go vet ./...
	staticcheck ./...
test:
	go test -race -timeout 1m -covermode=atomic -coverprofile cover.out ./...
testshort:
	go test -short -race -timeout 1m -covermode=atomic -coverprofile cover.out ./...
coverreport:
	go tool cover -html=cover.out -o cover.html
	open cover.html
clean:
	go clean
