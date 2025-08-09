build: bin/hide

bin/hide: *.go
	go build -o bin/hide ./...

test: 
	go test ./...
