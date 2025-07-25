# Use official Python image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libpq-dev \
       git \
       gettext \
       dos2unix \
       netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /usr/src/app

# Install dependencies
COPY requirements.txt /usr/src/app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project files
COPY . /usr/src/app/

# Convert line endings and make entrypoint executable
RUN dos2unix /usr/src/app/entrypoint.sh && chmod +x /usr/src/app/entrypoint.sh

# Expose default Render port (Render binds to $PORT, usually 10000)
EXPOSE 10000

# Start with entrypoint script
CMD ["/usr/src/app/entrypoint.sh"]
