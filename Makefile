build:
	docker-compose build

rebuild:
	docker-compose build --no-cache

up:
	docker-compose up

up-daemon:
	docker-compose up -d

stop:
	docker-compose stop

pretty:
	black -l 110 **/*.py
	isort -y -s Api/app/__init__.py **/*.py
