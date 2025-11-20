# Makefile for MITRE ATT&CK Hierarchy Parser
.PHONY: help install install-dev clean format lint type-check test test-unit test-integration test-coverage ci build publish pre-commit download-fixtures

# Default target
help:
	@echo "MITRE ATT&CK Hierarchy Parser - Development Commands"
	@echo ""
	@echo "Setup Commands:"
	@echo "  make install          - Install package dependencies with uv"
	@echo "  make install-dev      - Install package with development dependencies"
	@echo "  make pre-commit       - Install pre-commit hooks"
	@echo "  make download-fixtures - Download enterprise-attack.json test fixture"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  make format           - Format code with black and isort"
	@echo "  make lint             - Run linting with pylint"
	@echo "  make type-check       - Run type checking with mypy"
	@echo "  make ci               - Run full CI pipeline (format, lint, type-check, test)"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make test             - Run all tests"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make test-coverage    - Run tests and open HTML coverage report"
	@echo ""
	@echo "Build & Release Commands:"
	@echo "  make build            - Build distribution packages"
	@echo "  make publish          - Publish to PyPI (requires credentials)"
	@echo "  make publish-test     - Publish to TestPyPI"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  make clean            - Remove build artifacts and cache files"

# Setup commands
install:
	uv sync

install-dev:
	uv sync --extra dev

pre-commit:
	.venv/bin/pre-commit install
	@echo "Pre-commit hooks installed"

download-fixtures:
	@echo "Downloading enterprise-attack.json test fixture..."
	@mkdir -p tests/fixtures
	@curl -fsSL -o tests/fixtures/enterprise-attack.json \
		https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
	@echo "Test fixture downloaded to tests/fixtures/enterprise-attack.json"

# Code formatting
format:
	@echo "Formatting code with black..."
	.venv/bin/black src/attack_hierarchy/ tests/
	@echo "Sorting imports with isort..."
	.venv/bin/isort src/attack_hierarchy/ tests/
	@echo "Code formatting complete"

# Linting
lint:
	@echo "Running pylint on source code..."
	.venv/bin/pylint --rcfile=.pylintrc src/attack_hierarchy/
	@echo "Running pylint on tests..."
	.venv/bin/pylint --rcfile=.pylintrc-tests tests/
	@echo "Linting complete"

# Type checking
type-check:
	@echo "Running mypy type checker on source code..."
	.venv/bin/mypy src/attack_hierarchy/
	@echo "Running mypy type checker on tests..."
	.venv/bin/mypy tests/ || true
	@echo "Type checking complete"

# Security scanning
security:
	@echo "Running security scan with bandit..."
	.venv/bin/bandit -c .bandit -r src/attack_hierarchy/ -f json -o bandit-report.json --severity-level medium || \
	.venv/bin/bandit -c .bandit -r src/attack_hierarchy/ --severity-level medium
	@echo "Security scan complete"

# Testing
test:
	@echo "Running all tests..."
	.venv/bin/pytest -v
	@echo "All tests complete"

test-unit:
	@echo "Running unit tests..."
	.venv/bin/pytest tests/unit/ -v
	@echo "Unit tests complete"

test-integration:
	@echo "Running integration tests..."
	.venv/bin/pytest tests/integration/ -v
	@echo "Integration tests complete"

test-coverage:
	@echo "Running tests with coverage..."
	.venv/bin/pytest -v
	@echo "Opening coverage report..."
	.venv/bin/python -m webbrowser htmlcov/index.html || open htmlcov/index.html || xdg-open htmlcov/index.html
	@echo "Coverage report generated"

# CI pipeline
ci: format lint type-check security test
	@echo "CI pipeline complete - all checks passed!"

# Build and publish
build: clean
	@echo "Building distribution packages..."
	uv build
	@echo "Build complete - packages in dist/"

publish: build
	@echo "Publishing to PyPI..."
	uvx twine upload dist/*
	@echo "Published to PyPI"

publish-test: build
	@echo "Publishing to TestPyPI..."
	uvx twine upload --repository testpypi dist/*
	@echo "Published to TestPyPI"

# Cleanup
clean:
	@echo "Cleaning up..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf pytest-results.xml
	rm -rf pytest-report.html
	rm -rf bandit-report.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	@echo "Cleanup complete"
