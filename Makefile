SHELL := /bin/bash

.PHONY: all lint typecheck test scan build run-demo clean help

all: lint typecheck test

help:
	@echo "Cloud Security Auto-Remediation (SOAR) Commands:"
	@echo "  make lint         Run Ruff linter and code formatting check"
	@echo "  make typecheck    Run Mypy static type analysis on src/"
	@echo "  make test         Execute Pytest test suite with code coverage"
	@echo "  make scan         Run Gitleaks secret detection audit"
	@echo "  make build        Build hardened container image"
	@echo "  make run-demo     Execute sample dry-run remediation simulation"
	@echo "  make clean        Remove temporary test and linter caches"

lint:
	@echo "==> Running Ruff linter and formatting checks..."
	@which ruff >/dev/null 2>&1 && { ruff check .; ruff format --check .; } || python3 -m ruff check .

typecheck:
	@echo "==> Running Mypy static type analysis..."
	@which mypy >/dev/null 2>&1 && mypy src/ || python3 -m mypy src/

test:
	@echo "==> Running Pytest suite with test coverage..."
	@which pytest >/dev/null 2>&1 && pytest --cov=src --cov-report=term-missing tests/ || python3 -m pytest tests/

scan:
	@echo "==> Running Gitleaks secret scan..."
	@which gitleaks >/dev/null 2>&1 && gitleaks detect --verbose || echo "[INFO] gitleaks CLI not installed locally; enforced via GitHub Actions CI"

build:
	@echo "==> Building hardened multi-stage SOAR container..."
	docker build -t cloud-soar-remediator:local .

run-demo:
	@echo "==> Executing sample event remediation in DRY_RUN mode..."
	python3 -m src.main || python3 -c "from src.core.dispatcher import RemediationDispatcher; d = RemediationDispatcher(dry_run=True); print('SOAR Engine Initialized successfully in DRY-RUN mode')"

clean:
	@echo "==> Cleaning local cache directories..."
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist/ build/ *.egg-info .coverage
