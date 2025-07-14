# --- Configuration ---
APP_MODULE=main:app
HOST=0.0.0.0
PORT=8080
RELOAD=true

# --- Commands ---

.PHONY: help run install dev lint test clean

help:
	@echo "Usage:"
	@echo "  make install     - Install dependencies"
	@echo "  make run         - Run FastAPI app with Uvicorn"
	@echo "  make dev         - Run app in dev mode (with reload)"
	@echo "  make lint        - Run linter (ruff or flake8)"
	@echo "  make test        - Run tests (pytest)"
	@echo "  make clean       - Remove __pycache__ and .pytest_cache"

install:
	@if [ -f pyproject.toml ]; then \
		poetry install; \
	else \
		pip install -r requirements.txt; \
	fi

run:
	uvicorn $(APP_MODULE) --host $(HOST) --port $(PORT)

dev:
	uvicorn $(APP_MODULE) --host $(HOST) --port $(PORT) --reload

lint:
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check .; \
	elif command -v flake8 >/dev/null 2>&1; then \
		flake8 .; \
	else \
		echo "No linter found (install ruff or flake8)"; \
	fi

test:
	pytest

clean:
	find . -type d -name "__pycache__" -exec rm -r {} +;
	rm -rf .pytest_cache