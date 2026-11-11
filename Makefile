.PHONY: install dev lint test clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

lint:
	ruff check injection_fuzzer/ tests/

fix:
	ruff check --fix injection_fuzzer/ tests/

test:
	pytest tests/ -v

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

list:
	injection-fuzzer list-payloads
