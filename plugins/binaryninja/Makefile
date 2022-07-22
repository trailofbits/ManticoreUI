mkfile_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

init:
	mkdir -p $(mkfile_dir)mui/common_resources/
	cp $(mkfile_dir)../common/* $(mkfile_dir)mui/common_resources/
	test -d venv || python3 -m venv venv
	. venv/bin/activate; pip install -r requirements-dev.txt -r binjastub/requirements.txt

format:
	black .

lint:
	black --check .
	mypy

test:
	pytest
