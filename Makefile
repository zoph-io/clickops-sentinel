# ClickOps Notifier build and deployment tasks.
#
# Prerequisites: AWS SAM CLI, Python 3.13, GNU make.
# Usage: make help

STACK_NAME ?= clickops-notifier
REGION ?= $(shell aws configure get region 2>/dev/null || echo us-east-1)
PYTHON ?= python3
VENV := .venv
DAYS ?= 30

.PHONY: help install build test lint validate deploy deploy-guided delete stats clean

help:
	@echo "ClickOps Notifier"
	@echo ""
	@echo "  make install         Create a virtualenv and install dev dependencies"
	@echo "  make build           Build the SAM application"
	@echo "  make test            Run unit tests"
	@echo "  make lint            Run ruff linting"
	@echo "  make validate        Validate the SAM template"
	@echo "  make deploy-guided   First deployment, prompts for all parameters"
	@echo "  make deploy          Deploy using saved samconfig.toml values"
	@echo "  make stats           Print investigation statistics (DAYS=30)"
	@echo "  make delete          Delete the stack"
	@echo ""
	@echo "  Variables: STACK_NAME=$(STACK_NAME) REGION=$(REGION)"

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements-dev.txt

build:
	sam build

test:
	$(VENV)/bin/pytest tests/ -v

lint:
	$(VENV)/bin/ruff check src/ tests/ scripts/

validate:
	sam validate --lint --region $(REGION)

deploy-guided: build
	sam deploy --guided --stack-name $(STACK_NAME) --region $(REGION) \
		--capabilities CAPABILITY_IAM

deploy: build
	sam deploy --stack-name $(STACK_NAME) --region $(REGION) \
		--capabilities CAPABILITY_IAM --no-confirm-changeset

stats:
	$(VENV)/bin/python scripts/stats.py --stack-name $(STACK_NAME) --region $(REGION) --days $(DAYS)

delete:
	sam delete --stack-name $(STACK_NAME) --region $(REGION)

clean:
	rm -rf .aws-sam $(VENV) .pytest_cache .ruff_cache
