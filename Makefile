SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON ?= .venv/bin/python
IMAGE ?= cloud-soar-remediator:local
.PHONY: help setup lint typecheck test scan build plan run-demo
help:
	@echo 'setup, lint, typecheck, test, scan (Gitleaks), build (Docker), plan/run-demo (offline)'
setup:
	python3 -m venv .venv
	$(PYTHON) -m pip install -e '.[dev]'
lint:
	$(PYTHON) -m ruff check .
typecheck:
	$(PYTHON) -m mypy src/
test:
	$(PYTHON) -m pytest --cov=src --cov-report=term-missing tests/
scan:
	gitleaks detect --source . --redact
build:
	docker build -t "$(IMAGE)" .
plan:
	$(PYTHON) -m src.main
run-demo: plan
