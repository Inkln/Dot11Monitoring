#!/bin/sh
rm -rf migrations
exec flask db init
exec flask db migrate
exec flask db upgrade
exec gunicorn -b :5000 --access-logfile - --error-logfile - api:app;