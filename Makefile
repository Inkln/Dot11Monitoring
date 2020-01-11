build:
	docker-compose build

rebuild:
	docker-compose build --no-cache

up:
	docker-compose up api

up-daemon:
	docker-compose up api -d

stop:
	docker-compose stop

pretty:
	black -l 110 **/*.py
	isort -y -s Api/app/__init__.py **/*.py

lint:
	pylint --rcfile .pylint Api

test:
	docker-compose up --build --abort-on-container-exit --exit-code-from test test
