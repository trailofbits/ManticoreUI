mkfile_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

init:
	cp $(mkfile_dir)../common/* $(mkfile_dir)mui/common_resources/
	test -d venv || python3 -m venv venv
	. venv/bin/activate; pip install -r requirements-dev.txt -r binjastub/requirements.txt

format:
	black .
	isort .

lint:
	black --check .
	isort --check .
	mypy

test:
	pytest
