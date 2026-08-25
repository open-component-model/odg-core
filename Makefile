.PHONY: help setup lint lint-staged format format-staged test build-clients build-core build-docker build-docker-local .check-build-prereqs run-db run clean

# Configuration variables with defaults
DB_PASSWORD ?= MyPassword
DB_HOST ?= 127.0.0.1
DB_PORT ?= 5432
DB_USER ?= postgres
DB_NAME ?= postgres
SERVER_PORT ?= 5000

# Default target
help:
	@echo "Available targets:"
	@echo "  setup         - Install development dependencies"
	@echo "  lint           - Run ruff and bandit linters"
	@echo "  lint-staged    - Run ruff linter on staged files only"
	@echo "  format         - Check code formatting with ruff"
	@echo "  format-staged  - Check and apply formatting to staged files only"
	@echo "  test           - Run pytest test suite"
	@echo "  build-clients  - Build bdba and odg client packages"
	@echo "  build-core     - Build odg-core-libs package"
	@echo "  build-docker   - Build Docker image"
	@echo "  build-docker-local - Build Docker image for current architecture only"
	@echo "  run-db         - Run a PostgreSQL database instance"
	@echo "  run            - Run the development server"
	@echo "  clean          - Remove build artifacts"
	@echo ""
	@echo "Run target options (with defaults):"
	@echo "  DB_PASSWORD=<password>  (default: MyPassword)"
	@echo "  DB_HOST=<host>          (default: 127.0.0.1)"
	@echo "  DB_PORT=<port>          (default: 5432)"
	@echo "  DB_USER=<user>          (default: postgres)"
	@echo "  DB_NAME=<database>      (default: postgres)"
	@echo "  SERVER_PORT=<port>      (default: 5000)"
	@echo ""
	@echo "Example: make run DB_PASSWORD=secret DB_HOST=localhost"

# Setup development environment
setup:
	@echo "Installing development dependencies..."
	@uv sync
	@echo "Generating RSA key pair as signing configuration..."
	@keypath=$$(mktemp); \
	unlink "$${keypath}"; \
	ssh-keygen -t rsa -b 4096 -f "$${keypath}" -m PEM -N "" < /dev/null; \
	private_key=$$(cat "$${keypath}"); \
	public_key=$$(openssl rsa -in "$${keypath}" -pubout -outform PEM 2>/dev/null); \
	unlink "$${keypath}"; \
	unlink "$${keypath}.pub"; \
	{ \
		printf 'algorithm: RS256\n'; \
		printf 'id: %s\n' "$$(uv run python3 -c 'import uuid; print(uuid.uuid4())')"; \
		printf 'private_key: |\n'; \
		echo "$${private_key}" | sed 's/^/  /'; \
		printf 'public_key: |\n'; \
		echo "$${public_key}" | sed 's/^/  /'; \
	} > src/secrets/signing-cfg/local.yaml
	@echo "Installing git hooks..."
	@git config core.hooksPath .githooks
	@echo "Setup complete"

# Linting
lint:
	@echo "Running linters..."
	@echo "Running ruff for all python modules..."
	@if uv run ruff check .; then \
		echo "ruff check succeeded"; \
	else \
		echo "ruff check failed, apply suggested fixes with: uv run ruff check --fix"; \
		exit 1; \
	fi
	@echo "Running bandit (sast-linter) for all modules..."
	@if uv run bandit --configfile pyproject.toml --recursive . $(bandit_extra_args); then \
		echo "bandit succeeded"; \
	else \
		echo "bandit failed"; \
		exit 1; \
	fi

# Linting for staged files only (used by pre-commit hook)
lint-staged:
	@echo "Running ruff lint on staged files..."
	@bash -c 'set -e; \
	mkdir -p /tmp/pre-commit-$$$$; \
	status=0; \
	while IFS= read -r -d "" file; do \
		mkdir -p "/tmp/pre-commit-$$$$/$$( dirname "$$file" )"; \
		git show ":$$file" > "/tmp/pre-commit-$$$$/$$file"; \
		if uv run ruff check --fix "/tmp/pre-commit-$$$$/$$file"; then \
			HASH=$$(git hash-object -w "/tmp/pre-commit-$$$$/$$file"); \
			MODE=$$(git ls-files --stage -z "$$file" | cut -d" " -f1); \
			git update-index --cacheinfo $$MODE,$$HASH,"$$file"; \
		else \
			status=1; \
		fi; \
	done < <(git diff --cached --name-only -z --diff-filter=ACMR -- "*.py"); \
	rm -rf /tmp/pre-commit-$$$$; \
	exit $$status'

# Format checking
format:
	@echo "Checking code formatting..."
	@if ! uv run ruff format --check .; then \
		echo ""; \
		echo "=============================================="; \
		echo " run 'uv run ruff format' to apply suggested changes "; \
		echo "=============================================="; \
		exit 1; \
	fi

# Format staged files only (used by pre-commit hook)
format-staged:
	@echo "Formatting staged files..."
	@bash -c 'set -e; \
	mkdir -p /tmp/pre-commit-$$$$; \
	status=0; \
	while IFS= read -r -d "" file; do \
		mkdir -p "/tmp/pre-commit-$$$$/$$( dirname "$$file" )"; \
		git show ":$$file" > "/tmp/pre-commit-$$$$/$$file"; \
		if uv run ruff format "/tmp/pre-commit-$$$$/$$file"; then \
			HASH=$$(git hash-object -w "/tmp/pre-commit-$$$$/$$file"); \
			MODE=$$(git ls-files --stage -z "$$file" | cut -d" " -f1); \
			git update-index --cacheinfo $$MODE,$$HASH,"$$file"; \
		else \
			status=1; \
		fi; \
	done < <(git diff --cached --name-only -z --diff-filter=ACMR -- "*.py"); \
	rm -rf /tmp/pre-commit-$$$$; \
	exit $$status'

# Testing
test:
	@echo "Running tests..."
	@if PYTHONPATH="$(CURDIR):$$PYTHONPATH" uv run pytest "$(CURDIR)"; then \
		echo "Unittest executions succeeded"; \
	else \
		echo "Errors were found whilst executing unittests (see above)"; \
		exit 1; \
	fi

# Build client packages (bdba and odg)
build-clients:
	@echo "Building client packages..."
	@mkdir -p dist
	@echo "Building bdba-client package..."
	@uv run --directory src python3 ../setup.bdba-client.py bdist_wheel --dist-dir ../dist
	@rm -rf src/build
	@echo "Building odg-client package..."
	@uv run --directory src python3 ../setup.odg-client.py bdist_wheel --dist-dir ../dist
	@rm -rf src/build
	@echo "Client packages built:"
	@ls -1 dist/

# Build core package
build-core:
	@echo "Building core package..."
	@mkdir -p dist
	@uv run python3 setup.py bdist_wheel --dist-dir dist
	@rm -rf build
	@echo "Core package built:"
	@ls -1 dist/

# Build Docker image
.check-build-prereqs:
	@if [ -z "$(ODG_CORE_LIBS_VERSION)" ]; then \
		echo "Error: ODG_CORE_LIBS_VERSION environment variable is required"; \
		echo "Usage: ODG_CORE_LIBS_VERSION=<version> make build-docker"; \
		exit 1; \
	fi
	@if [ ! -d "dist" ]; then \
		echo "Error: dist directory not found. Run 'make build-core' first."; \
		exit 1; \
	fi

build-docker: .check-build-prereqs
	@echo "Building Docker image..."
	@docker-buildx build \
		--build-arg ODG_CORE_LIBS_VERSION=$(ODG_CORE_LIBS_VERSION) \
		--platform linux/amd64,linux/arm64 \
		-t odg-core:$(ODG_CORE_LIBS_VERSION) \
		-f Dockerfile \
		.
	@echo "Docker image built: odg-core:$(ODG_CORE_LIBS_VERSION)"

# Build Docker image for current architecture only (local development)
build-docker-local: .check-build-prereqs
	@echo "Building Docker image (local arch)..."
	@docker-buildx build \
		--build-arg ODG_CORE_LIBS_VERSION=$(ODG_CORE_LIBS_VERSION) \
		--load \
		-t odg-core:$(ODG_CORE_LIBS_VERSION) \
		-f Dockerfile \
		.
	@echo "Docker image built: odg-core:$(ODG_CORE_LIBS_VERSION)"

# Run PostgreSQL database instance
run-db:
	@echo "Starting PostgreSQL database instance..."
	@echo "Database port: $(DB_PORT)"
	@docker run -dit --name postgres \
		-e "POSTGRES_USER=$(DB_USER)" \
		-e "POSTGRES_PASSWORD=$(DB_PASSWORD)" \
		-e "POSTGRES_DB=$(DB_NAME)" \
		-p "$(DB_PORT):5432" \
		postgres:16

# Run development server
run:
	@echo "Starting development server..."
	@echo "Database: postgresql+psycopg://$(DB_USER):****@$(DB_HOST):$(DB_PORT)/$(DB_NAME)"
	@echo "Server port: $(SERVER_PORT)"
	@PYTHONPATH=$(CURDIR)/src:$$PYTHONPATH uv run adev runserver \
		--port $(SERVER_PORT) \
		$(CURDIR)/src \
		-- \
		--delivery-db-url postgresql+psycopg://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf dist build src/*.egg-info
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Clean complete"
