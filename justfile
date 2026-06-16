set shell := ["bash", "-lc"]

install:
    @echo "Installing development tools..."
    @echo "Installing golangci-lint..."
    @go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0
    @if ! command -v goimports >/dev/null 2>&1; then \
        echo "Installing goimports..."; \
        go install golang.org/x/tools/cmd/goimports@latest; \
    fi
    @echo "✓ All tools installed"

fix:
    @echo "Running go fix..."
    @go fix ./...
    @echo "✓ go fix complete"

fmt:
    @echo "Formatting..."
    @find . -name '*.go' -not -path './scripts/*' -print0 | xargs -0 goimports -w
    @echo "✓ Formatting complete"

vet:
    @echo "Vetting..."
    @go vet ./...
    @echo "✓ Go vet passed"

build:
    @echo "Building..."
    @go build ./...
    @echo "✓ Build successful"

test *args:
    @echo "Running tests..."
    @if [ -z "{{args}}" ]; then \
        go test ./...; \
    else \
        go test {{args}}; \
    fi
    @echo "✓ Tests passed"

lint:
    @echo "Running linters..."
    @golangci-lint run --allow-parallel-runners ./...
    @echo "✓ Linters passed"

loc-check:
    @uv run --project scripts python scripts/loc_check.py --lang go --mode changed .

loc-check-full:
    @uv run --project scripts python scripts/loc_check.py --lang go --mode full .

check:
    @echo "Running code checks..."
    @echo ""
    @just fix
    @echo ""
    @echo "Running goimports..."
    @find . -name '*.go' -not -path './scripts/*' -print0 | xargs -0 goimports -w
    @echo "✓ goimports complete"
    @echo ""
    @echo "Running go mod tidy..."
    @go mod tidy
    @echo "✓ Go mod tidy complete"
    @echo ""
    @echo "Running go vet..."
    @go vet ./...
    @echo "✓ Go vet passed"
    @echo ""
    @echo "Running go build..."
    @go build ./...
    @echo "✓ Go build passed"
    @echo ""
    @echo "Running tests..."
    @go test ./...
    @echo "✓ Tests passed"
    @echo ""
    @echo "Running LOC check..."
    @just loc-check
    @echo ""
    @echo "Running linters..."
    @golangci-lint run --allow-parallel-runners ./...
    @echo "✓ Linters passed"
    @echo ""
    @echo "✓ All checks complete"
