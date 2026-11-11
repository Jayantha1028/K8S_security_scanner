.PHONY: test lint clean install run-all audit

install:
	pip install -e .

test:
	python3 -m unittest discover tests

lint:
	python3 -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf *.egg-info build dist .coverage
