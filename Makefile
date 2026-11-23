# Convenience targets. Everything here is also available as npm scripts or plain docker compose.
COMPOSE = docker compose --env-file deploy/.env

.PHONY: help install setup dev lint test build smoke check up down logs ps images

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-15s %s\n", $$1, $$2}'

install: ## Install dependencies (exact versions from the lockfile)
	npm ci

setup: ## Create ./secrets and a local .env (keeps existing secrets)
	node scripts/gen-secrets.mjs
	@test -f deploy/.env || cp deploy/.env.example deploy/.env

dev: ## Run authority, API and Vite dev server (needs MongoDB on localhost)
	npm run dev

lint: ## ESLint
	npm run lint

test: ## Unit and integration tests (crypto, authority, API, client)
	npm test

build: ## Build the web client
	npm run build

smoke: ## End-to-end test against running services (set BASE_URL or API_URL/AUTHORITY_URL)
	npm run smoke

check: lint test build ## Everything CI runs before the image builds
	npm run audit:prod

up: setup ## Build images and start the full stack with TLS
	$(COMPOSE) up -d --build

down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

logs: ## Follow service logs
	$(COMPOSE) logs -f --tail 100

ps: ## Show container status and health
	$(COMPOSE) ps

images: ## Build the three images without starting them
	$(COMPOSE) build
