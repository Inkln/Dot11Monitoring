build:
	docker-compose build

rebuild:
	docker-compose build --no-cache

up:
	docker-compose up

up-daemon:
	docker-compose up -d db