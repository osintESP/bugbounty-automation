FROM python:3.11-slim

LABEL maintainer="Bug Bounty Automation Tool"
LABEL description="Docker image with security tools for bug bounty automation"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    unzip \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    masscan \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for many security tools)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install security tools
# Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# Assetfinder
RUN go install -v github.com/tomnomnom/assetfinder@latest

# Httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Gospider
RUN go install -v github.com/jaeles-project/gospider@latest

# Hakrawler
RUN go install -v github.com/hakluke/hakrawler@latest

# Katana
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Gau (Get All URLs)
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# Ffuf
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Dalfox (XSS scanner)
RUN go install -v github.com/hahwul/dalfox/v2@latest

# Update Nuclei templates
RUN nuclei -update-templates

# Create application directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose port for API/Dashboard
EXPOSE 8000

# Default command
CMD ["python", "src/main.py", "--help"]
