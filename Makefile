init:
	git submodule update --init --recursive
	test -d venv || virtualenv venv
	. venv/bin/activate; pip install -r requirements-dev.txt -r requirements.txt

format:
	black .

lint:
	black --check .
	mypy

test:
	pytest
