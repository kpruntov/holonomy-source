# @trace TASK-037
.PHONY: test test-integration test-perf

# Ensure DOCKER_HOST is set to podman socket for testcontainers if running integration tests
PODMAN_SOCKET ?= unix:///run/user/$(shell id -u)/podman/podman.sock

# Note on WSL memory exhaustion: Testcontainers can spin up many heavy containers (e.g. LocalStack, Azurite).
# If WSL crashes, ensure your %USERPROFILE%\.wslconfig limits memory (e.g., memory=8GB).
# We append -- --test-threads=1 to limit test concurrency and prevent overwhelming the system.

test: test-python
	@echo "Running all tests (including integration tests requiring Podman)..."
	DOCKER_HOST=$(PODMAN_SOCKET) cargo test -- --test-threads=1

test-python:
	@echo "Running Python integration tests..."
	cd holonomy-py && . .venv/bin/activate && maturin develop && pytest tests/

test-integration:
	@echo "Running Azure integration tests requiring Podman..."
	DOCKER_HOST=$(PODMAN_SOCKET) cargo test --package holonomy-core --test azure_integration_tests -- --test-threads=1

test-perf:
	@echo "Running performance-sensitive tests in release mode..."
	DOCKER_HOST=$(PODMAN_SOCKET) cargo test --release -- --test-threads=1
