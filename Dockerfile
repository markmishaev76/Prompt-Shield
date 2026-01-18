FROM python:3.11-slim

LABEL maintainer="markmishaev76"
LABEL org.opencontainers.image.source="https://github.com/markmishaev76/Prompt-Shield"
LABEL org.opencontainers.image.description="Prompt Shield - Protect AI agents from indirect prompt injection"

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY src/ ./src/
COPY integrations/ ./integrations/
COPY entrypoint.sh .

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Set Python path
ENV PYTHONPATH=/app/src

ENTRYPOINT ["/app/entrypoint.sh"]
