#!/bin/bash

# Wait for database to be ready (optional, useful if using Render DB)
echo "Waiting for database..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "Database is up."

# Apply migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Execute CMD
exec "$@"
