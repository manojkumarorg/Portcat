# Dockerfile for local development/testing

FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies and RustScan
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl ca-certificates unzip \
    && curl -fL https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip -o rustscan.deb.zip \
    && unzip rustscan.deb.zip \
    && dpkg -i rustscan_2.4.1-1_amd64.deb \
    && rm rustscan_2.4.1-1_amd64.deb rustscan.deb.zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]