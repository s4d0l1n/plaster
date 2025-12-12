FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY plaster_server.py wordlist.py .

# Create config directory
RUN mkdir -p /root/.plaster

# Expose port
EXPOSE 9321

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:9321/health')" || exit 1

# Run the application
CMD ["python", "plaster_server.py"]
