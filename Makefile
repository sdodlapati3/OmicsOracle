# OmicsOracle Makefile

.PHONY: help install install-dev test test-cov lint format type-check clean build docker run docs serve

# Variables
PYTHON := python3
PIP := pip
VENV := venv
SOURCE_DIR := src/omics_oracle
TEST_DIR := tests

# Default target
help:
	@echo "Available commands:"
	@echo "  install       - Install production dependencies"
	@echo "  install-dev   - Install development dependencies"
	@echo "  test          - Run tests"
	@echo "  test-cov      - Run tests with coverage"
	@echo "  lint          - Run linting"
	@echo "  format        - Format code"
	@echo "  type-check    - Run type checking"
	@echo "  clean         - Clean build artifacts"
	@echo "  build         - Build package"
	@echo "  docker        - Build Docker image"
	@echo "  run           - Run the application"
	@echo "  docs          - Build documentation"
	@echo "  serve         - Serve documentation locally"

# Installation
install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements-dev.txt
	pre-commit install

# Testing
test:
	pytest $(TEST_DIR) -v

test-cov:
	pytest $(TEST_DIR) --cov=$(SOURCE_DIR) --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 $(SOURCE_DIR) $(TEST_DIR)
	bandit -r $(SOURCE_DIR)

format:
	black $(SOURCE_DIR) $(TEST_DIR)
	isort $(SOURCE_DIR) $(TEST_DIR)

type-check:
	mypy $(SOURCE_DIR)

# Code quality all-in-one
quality: format lint type-check

# Cleaning
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Building
build: clean
	$(PYTHON) -m build

# Docker
docker:
	docker build -t omics-oracle .

docker-compose:
	docker-compose up --build

# Running
run:
	uvicorn omics_oracle.api.main:app --reload --host 0.0.0.0 --port 8000

run-cli:
	$(PYTHON) -m omics_oracle.cli

# Documentation
docs:
	mkdocs build

serve:
	mkdocs serve

# Development workflow
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make run' to start the API server"
	@echo "Run 'make docs' to build documentation"

# CI workflow
ci: install-dev quality test-cov

# Production deployment
deploy: build docker
	@echo "Production deployment artifacts ready"

# Database setup
db-setup:
	@echo "Setting up databases..."
	docker-compose up -d mongodb redis
	@echo "Databases started"

# Full development environment
dev-full: dev-setup db-setup
	@echo "Full development environment ready!"
	@echo "API: http://localhost:8000"
	@echo "Docs: http://localhost:8000/docs"
	@echo "MongoDB: mongodb://localhost:27017"
	@echo "Redis: redis://localhost:6379"
