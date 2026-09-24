GO        ?= go
PKGS      := $(shell $(GO) list ./... | grep -v /examples/)
COVER_OUT := coverage.out

.PHONY: lint vuln test test-integration cover fuzz generate console-build redaction-scan e2e compose-up compose-down

lint:
	$(GO) vet ./...
	golangci-lint run ./...

vuln:
	../../scripts/vulncheck.sh

test:
	$(GO) test -race -count=1 ./...

test-integration:
	$(GO) test -race -count=1 -tags integration ./tests/integration/...

# Unit coverage is measured over packages that carry logic. Generated protobuf
# code, the SQL bindings (internal/store, */*db), the wiring (internal/app, cmd,
# examples) and the test packages are exercised by the tagged integration suite
# (make test-integration) and are excluded from the unit gate on purpose.
COVERPKG := $(shell $(GO) list ./... | grep -v -E '/api/proto/|/internal/store$$|db$$|/internal/app$$|/cmd/|/examples/|/tests/|/console$$' | paste -sd, -)

cover:
	$(GO) test -count=1 -coverprofile=$(COVER_OUT) -coverpkg=$(COVERPKG) $(PKGS)
	./scripts/coverage-gate.sh $(COVER_OUT)

fuzz:
	for f in FuzzSlug FuzzPermissionRef FuzzFGAObjectID FuzzTokenParse FuzzJWKS FuzzTOTPCode FuzzRecoveryCode FuzzRecoveryToken; do \
	  $(GO) test -run xxx -fuzz=$$f -fuzztime=20s ./tests/fuzz/ || exit 1; done

generate:
	buf generate
	cd sdk && buf generate

console-build:
	cd console && npm ci && npm run build

redaction-scan:
	./scripts/redaction-scan.sh

e2e:
	cd console && npx playwright test

compose-up:
	docker compose -f deploy/compose.yaml up -d

compose-down:
	docker compose -f deploy/compose.yaml down -v
