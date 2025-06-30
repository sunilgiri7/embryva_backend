FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    PORT=8080

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create entrypoint script inline to avoid extra file
RUN echo '#!/usr/bin/env sh\n\
set -e\n\
python manage.py makemigrations --no-input\n\
python manage.py migrate --no-input\n\
exec "$@"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# EXPOSE $PORT
EXPOSE 10000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sh", "-c", "gunicorn embryva_backend.wsgi:application --bind 0.0.0.0:$PORT"]