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

image:
	docker build -t $(NAME):latest . \
		--build-arg BUILD_VERSION=$(VERSION) \
		--build-arg BUILD_DATE="$(DATE)" 

	docker system prune -f

container:
	docker run --rm -p 4320:4320 $(NAME):latest