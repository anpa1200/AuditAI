FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST_ROOT=/host \
    OUTPUT_DIR=/output

# Install system security tools and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Scanning tools
    nmap \
    lynis \
    # Network tools
    iproute2 \
    net-tools \
    iputils-ping \
    iptables \
    nftables \
    # Process/system tools
    procps \
    lsof \
    util-linux \
    psmisc \
    # Capability tools
    libcap2-bin \
    # Audit
    auditd \
    # Package management helpers
    apt-utils \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Misc
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY assessment/ ./assessment/

# Create output directory
RUN mkdir -p /output

# Run as root (required for raw socket nmap scans and /proc reads)
USER root

ENTRYPOINT ["python3", "-m", "assessment.cli"]
CMD ["--help"]
