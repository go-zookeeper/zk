# make file to hold the logic of build and test setup
ZK_VERSION ?= 3.5.6

ZK = apache-zookeeper-$(ZK_VERSION)-bin
ZK_URL = "https://archive.apache.org/dist/zookeeper/zookeeper-$(ZK_VERSION)/$(ZK).tar.gz"

PACKAGES := $(shell go list ./... | grep -v examples)

.DEFAULT_GOAL := test

$(ZK):
	wget $(ZK_URL)
	tar -zxf $(ZK).tar.gz
	rm $(ZK).tar.gz

zookeeper: $(ZK)
	# we link to a standard directory path so then the tests dont need to find based on version
	# in the test code. this allows backward compatable testing.
	ln -s $(ZK) zookeeper

.PHONY: setup
setup: zookeeper

.PHONY: lint
lint:
	go fmt ./...
	go vet ./...

.PHONY: build
build:
	go build ./...

.PHONY: test
test: build zookeeper
	go test -timeout 500s -v -race -covermode atomic -coverprofile=profile.cov $(PACKAGES)

.PHONY: clean
clean:
	rm -f apache-zookeeper-*.tar.gz
	rm -f zookeeper-*.tar.gz
	rm -rf apache-zookeeper-*/
	rm -rf zookeeper-*/
	rm -f zookeeper
	rm -f profile.cov

.PHONY: jute
jute:
	go run github.com/go-zookeeper/jute/cmd/jutec \
		-go.moduleMap=org.apache.zookeeper: \
		-go.prefix=github.com/go-zookeeper/zk/internal \
		-outDir internal \
		jute/zookeeper.jute
	rm -rf internal/server
