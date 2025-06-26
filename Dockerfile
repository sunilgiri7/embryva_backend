FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    PORT=8080

WORKDIR /app

# Install git (for git-based pip dependencies)
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# requirements first (leverages Docker cache)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# project code
COPY . .

# entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN python manage.py collectstatic --noinput

EXPOSE $PORT

ENTRYPOINT ["/entrypoint.sh"]

# Use environment variable for port
CMD ["sh", "-c", "gunicorn embryva_backend.wsgi:application --bind 0.0.0.0:$PORT"]