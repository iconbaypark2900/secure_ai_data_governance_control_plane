# Common tasks. `make help` lists them.

SHELL := /bin/bash
PY := .venv/bin/python
UV := uv
export CP_DATABASE_URL ?= postgresql+asyncpg://control_plane:control_plane@localhost:5432/control_plane

.DEFAULT_GOAL := help
.PHONY: help install secrets dev-db serve seed discover demo test test-pg lint fmt typecheck \
        check migrate migration ui ui-dev up down logs clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtualenv and install everything
	$(UV) venv --python 3.13
	$(UV) pip install -e '.[dev]'
	$(UV) pip install -e ./sdk/python
	@echo "installed. next: make secrets && make dev-db && make migrate && make seed"

secrets: ## Generate the two required keys into .env
	@test -f .env || cp .env.example .env
	@$(PY) -c "import secrets,pathlib,re; \
p=pathlib.Path('.env'); t=p.read_text(); \
t=re.sub(r'^CP_AUDIT_HMAC_KEY=.*$$','CP_AUDIT_HMAC_KEY='+secrets.token_urlsafe(32),t,flags=re.M); \
t=re.sub(r'^CP_REDACTION_HMAC_KEY=.*$$','CP_REDACTION_HMAC_KEY='+secrets.token_urlsafe(32),t,flags=re.M); \
t=re.sub(r'^CP_TOKENIZATION_KEY=.*$$','CP_TOKENIZATION_KEY='+secrets.token_urlsafe(32),t,flags=re.M); \
t=re.sub(r'^CP_BOOTSTRAP_ADMIN_KEY=.*$$','CP_BOOTSTRAP_ADMIN_KEY=cpk_'+secrets.token_hex(4)+'_'+secrets.token_urlsafe(24),t,flags=re.M); \
p.write_text(t); print('wrote keys to .env')"
	@echo "back up CP_AUDIT_HMAC_KEY and CP_TOKENIZATION_KEY somewhere other than the database."
	@echo "losing the audit key stops the chain verifying; losing the tokenization key"
	@echo "makes every existing token permanently irreversible."

dev-db: ## Start a local Postgres for development
	docker run -d --name cp-postgres \
	  -e POSTGRES_USER=control_plane -e POSTGRES_PASSWORD=control_plane \
	  -e POSTGRES_DB=control_plane -p 5432:5432 postgres:17-alpine
	@until docker exec cp-postgres pg_isready -U control_plane >/dev/null 2>&1; do sleep 1; done
	@docker exec cp-postgres psql -U control_plane -d postgres \
	  -c "CREATE DATABASE control_plane_test" >/dev/null 2>&1 || true
	@echo "postgres ready on :5432"

migrate: ## Apply migrations
	.venv/bin/alembic upgrade head

migration: ## Generate a migration: make migration m="add widgets"
	.venv/bin/alembic revision --autogenerate -m "$(m)"

seed: ## Load the reference policy set and catalog
	.venv/bin/cpctl seed

discover: ## Preview discovery against a configured source: make discover s=warehouse
	.venv/bin/cpctl catalog discover $(s) --dry-run

serve: ## Run the API with reload
	.venv/bin/cpctl serve --reload

demo: ## Walk through the reference scenarios
	./scripts/demo.sh

ui: ## Build the admin UI
	cd ui && npm install && npm run build

ui-dev: ## Run the UI dev server against a local API
	cd ui && npm install && npm run dev

test: ## Run the test suite (SQLite)
	$(PY) -m pytest

test-pg: ## Run the suite including Postgres integration tests
	CP_TEST_POSTGRES_URL=postgresql+asyncpg://control_plane:control_plane@localhost:5432/control_plane_test \
	  $(PY) -m pytest

lint: ## Check formatting and lint rules
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .

fmt: ## Apply formatting and safe lint fixes
	.venv/bin/ruff format .
	.venv/bin/ruff check --fix .

typecheck: ## Run mypy
	.venv/bin/mypy control_plane

check: lint typecheck test ## Everything CI runs

up: ## Start the full stack with docker compose
	docker compose up --build -d
	@echo "control plane  http://localhost:8000/docs"
	@echo "governed proxy http://localhost:8100/v1/chat/completions"

down: ## Stop the stack
	docker compose down

logs: ## Follow the stack's logs
	docker compose logs -f --tail 100

clean: ## Remove build artefacts and caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
