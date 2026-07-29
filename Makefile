.PHONY: help setup lint format test build-clients build-core build-docker run-db run clean

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
	@echo "  lint          - Run ruff and bandit linters"
	@echo "  format        - Check code formatting with ruff"
	@echo "  test          - Run pytest test suite"
	@echo "  build-clients - Build bdba and odg client packages"
	@echo "  build-core    - Build odg-core-libs package"
	@echo "  build-docker  - Build Docker image"
	@echo "  run-db        - Run a PostgreSQL database instance"
	@echo "  run           - Run the development server"
	@echo "  clean         - Remove build artifacts"
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
	@pip3 install --break-system-packages -r requirements-dev.txt
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
		printf 'id: %s\n' "$$(python3 -c 'import uuid; print(uuid.uuid4())')"; \
		printf 'private_key: |\n'; \
		echo "$${private_key}" | sed 's/^/  /'; \
		printf 'public_key: |\n'; \
		echo "$${public_key}" | sed 's/^/  /'; \
	} > src/secrets/signing-cfg/local.yaml
	@echo "Setup complete"

# Linting
lint:
	@echo "Running linters..."
	@.ci/lint

# Format checking
format:
	@echo "Checking code formatting..."
	@.ci/check-format

# Testing
test:
	@echo "Running tests..."
	@bash .ci/test

# Build client packages (bdba and odg)
build-clients:
	@echo "Building client packages..."
	@mkdir -p dist
	@echo "Building bdba-client package..."
	@python3 setup.bdba-client.py bdist_wheel --dist-dir dist
	@rm -rf build
	@echo "Building odg-client package..."
	@python3 setup.odg-client.py bdist_wheel --dist-dir dist
	@rm -rf build
	@echo "Client packages built:"
	@ls -1 dist/

# Build core package
build-core:
	@echo "Building core package..."
	@mkdir -p dist
	@python3 setup.py bdist_wheel --dist-dir dist
	@rm -rf build
	@echo "Core package built:"
	@ls -1 dist/

# Build Docker image
build-docker:
	@echo "Building Docker image..."
	@if [ -z "$(ODG_CORE_LIBS_VERSION)" ]; then \
		echo "Error: ODG_CORE_LIBS_VERSION environment variable is required"; \
		echo "Usage: ODG_CORE_LIBS_VERSION=<version> make build-docker"; \
		exit 1; \
	fi
	@if [ ! -d "dist" ]; then \
		echo "Error: dist directory not found. Run 'make build-core' first."; \
		exit 1; \
	fi
	@docker build \
		--build-arg ODG_CORE_LIBS_VERSION=$(ODG_CORE_LIBS_VERSION) \
		--build-context dist=./dist \
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
	@PYTHONPATH=$(CURDIR)/src:$$PYTHONPATH adev runserver \
		--port $(SERVER_PORT) \
		$(CURDIR)/src \
		-- \
		--delivery-db-url postgresql+psycopg://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf dist build *.egg-info
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Clean complete"
