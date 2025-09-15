registry=$(GAR_LOCATION)-docker.pkg.dev/$(GCP_PROJECT)
repository = setagaya
tag=$(tag_name)
img=$(registry)/$(repository)/$(component):$(tag)
upstream = rakutentech

ifeq ($(GITHUB_REPOSITORY_OWNER), $(upstream))
	tag=$(tag_name)
else
	tag=$(GITHUB_REPOSITORY_OWNER)-$(tag_name)
endif

.PHONY: help
help:  ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run all tests
	go test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage analysis
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'
	@echo "Coverage report generated: coverage.html"

.PHONY: test-coverage-rbac
test-coverage-rbac: ## Run RBAC tests with coverage
	go test -v -race -coverprofile=rbac_coverage.out ./rbac/...
	go tool cover -html=rbac_coverage.out -o rbac_coverage.html
	go tool cover -func=rbac_coverage.out | grep total | awk '{print "RBAC coverage: " $$3}'
	@echo "RBAC coverage report generated: rbac_coverage.html"

.PHONY: test-unit
test-unit: ## Run unit tests only
	go test -v -race -short ./...

.PHONY: lint
lint: ## Run linter
	which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.54.2
	golangci-lint run

.PHONY: clean-test
clean-test: ## Clean test artifacts
	rm -f coverage.out coverage.html rbac_coverage.out rbac_coverage.html

.PHONY: api_build
api_build:
	sh build.sh

.PHONY: api_image
api_image: api_build
	docker build -t $(img) -f Dockerfile .
	docker push $(img)

.PHONY: controller_build
controller_build:
	sh build.sh controller

.PHONY: controller_image
controller_image: controller_build
	docker build -t $(img) -f Dockerfile --build-arg="binary_name=setagaya-controller" .
	docker push $(img)

.PHONY: helm_charts
helm_charts:
	helm package install/setagaya

.PHONY: jmeter_agent
jmeter_agent:
	sh build.sh jmeter

.PHONY: jmeter_agent_image
jmeter_agent_image: jmeter_agent
	docker build -t $(img) -f Dockerfile.engines.jmeter .
	docker push $(img)


