PYTHON ?= python

.PHONY: install test server bot compose

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

server:
	$(PYTHON) -m app.server

bot:
	$(PYTHON) -m app.telegram_bot

compose:
	docker compose up --build
