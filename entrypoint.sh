#!/usr/bin/env sh
set -e

# Apply pending migrations (safe to run every start‑up)
python manage.py makemigrations --no-input
python manage.py migrate --no-input

# python manage.py collectstatic --noinput

# The container’s main process (passed from CMD or docker‑compose command)
exec "$@"