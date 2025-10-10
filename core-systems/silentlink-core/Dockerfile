# Dockerfile for silentlink-core
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port (if needed)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD python -c "import asyncio; from main import SilentlinkcoreCore; \
                 core = SilentlinkcoreCore(); \
                 result = asyncio.run(core.health_check()); \
                 exit(0 if result['status'] == 'healthy' else 1)"

# Run application
CMD ["python", "main.py"]
