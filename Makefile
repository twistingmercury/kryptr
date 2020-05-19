default: build

VERSION=v0.0.1
DATE=$(shell date)
NAME=kryptr

clean:
	go clean
	rm -rf ./_bin/$(NAME)

build: clean
	go get -v ./...
	go build -v -ldflags="-X 'main.Version=$(VERSION)' -X 'main.Date=$(DATE)'" -o ./_bin/$(NAME)


run: build
	./_bin/$(NAME)

sec: 
	./_bin/$(NAME)

test:
	go test -v ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

release:
	rm -rf ./_publish/linux/
	rm -rf ./_publish/darwin/
	rm -rf ./_publish/windows/
	go get -v ./... 
	GOOS=darwin GOARCH=amd64 go build -v -ldflags="-X 'main.Version=$(VERSION)' -X 'main.Date=$(DATE)'" -o ./_publish/darwin/$(NAME)
	GOOS=linux GOARCH=amd64 go build -v -ldflags="-X 'main.Version=$(VERSION)' -X 'main.Date=$(DATE)'" -o ./_publish/linux/$(NAME)

install-mac: release
	mv ./_publish/darwin/$(NAME) /usr/local/bin/$(NAME)

install-linux: release
	mv ./_publish/linux/$(NAME) /usr/local/bin/$(NAME)