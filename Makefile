init:
	git submodule update --init --recursive
	test -d venv || python3 -m venv venv
	. venv/bin/activate; pip install -r requirements-dev.txt -r requirements.txt

format:
	black .

lint:
	black --check .
	mypy

test:
	pytest
