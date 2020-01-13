#!/bin/sh

rm -rf migrations;
flask db init;

while true; do
    if flask db migrate 2>&1 | grep -i "psycopg2.OperationalError";
    then
        echo 'DB MIGRATE ERROR, COULD NOT CONNECT TO DATABASE';
        sleep 1;
    else
        echo 'DB MIGRATED SUCCESSFULLY'
        break;
    fi;
done;

while true; do
    if flask db upgrade 2>&1 | grep -i "psycopg2.OperationalError";
    then
        echo 'DB UPGRADE ERROR, COULD NOT CONNECT TO DATABASE';
        sleep 1;
    else
        echo 'DB UPGRADED SUCCESSFULLY'
        break;
    fi;
done;

echo 'DB IS INITIALISED, READY TO START TESTS'

coverage run -m pytest -s tests/*.py
status_code=$?
coverage report -m
exit $status_code