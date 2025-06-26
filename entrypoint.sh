#!/bin/sh

# Use fallback values if not set
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}

echo "Using DB_HOST=$DB_HOST"
echo "Waiting for DB at $DB_HOST:$DB_PORT..."

while ! nc -z "$DB_HOST" "$DB_PORT"; do
  echo "Waiting for database connection at $DB_HOST:$DB_PORT..."
  sleep 2
done

echo "Database is up - running migrations and starting server..."

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn embryva_backend.wsgi:application --bind 0.0.0.0:${PORT:-10000} --workers 3 --timeout 120
