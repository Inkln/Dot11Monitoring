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

coverage run -m pytest -s tests/monitor_tests.py #tests/*.py
status_code=$?
coverage report -m --omit="tests/*","__init__.py" --include="**/*.py" --fail-under 90
coverage_status=$?
if [[ $coverage_status -eq 2 ]];
then
    echo "ERROR: Code coverage is less then expected";
    exit 2;
fi;
exit $status_code