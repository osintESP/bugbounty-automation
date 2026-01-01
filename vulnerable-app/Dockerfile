FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create welcome file for path traversal testing
RUN echo "Welcome to the vulnerable web application!" > welcome.txt

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]
