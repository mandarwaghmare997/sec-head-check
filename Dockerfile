FROM python:3.9-slim

LABEL maintainer="Vulnuris Security <contact@vulnuris.com>"
LABEL description="sec-head-check: HTTP Security Headers Checker CLI Tool"

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash seccheck
USER seccheck

# Set entrypoint
ENTRYPOINT ["sec-head-check"]

# Default command shows help
CMD ["--help"]

