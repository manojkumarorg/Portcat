#!/usr/bin/env bash
TARGET="$1"                  # e.g., "10.1.75.0/24"
BATCH=10                   # batch safe for 1024 ulimit
ULIMIT=10
OUTBASE="scan_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <CIDR>" >&2
  exit 1
fi

SCAN_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Run RustScan to get open ports per IP
RUSTSCAN_OUT=$(rustscan -a "$TARGET" -b "$BATCH" --ulimit "$ULIMIT" --range 1-65535 --scan-order "serial" -g)

# Parse RustScan output and run Nmap for each IP with open ports
RESULTS="["
FIRST=1
for IP in $(echo "$RUSTSCAN_OUT" | cut -d: -f1 | sort | uniq); do
  PORTS=$(echo "$RUSTSCAN_OUT" | grep "^$IP:" | cut -d: -f2 | paste -sd, -)
  if [ -z "$PORTS" ]; then
    continue
  fi
  # Run Nmap for service detection
  NMAP_OUT=$(nmap -sV -p "$PORTS" "$IP")
  # Parse Nmap output for service names
  SERVICES="["
  while read -r LINE; do
    # Example: "22/tcp   open  ssh"
    if [[ $LINE =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([a-zA-Z0-9_-]+) ]]; then
      PORT="${BASH_REMATCH[1]}"
      SERVICE="${BASH_REMATCH[2]}"
      SERVICES+="{\"port\":\"$PORT\",\"service\":\"$SERVICE\"},"
    fi
  done < <(echo "$NMAP_OUT" | grep "/tcp" | grep open)
  SERVICES=${SERVICES%,}] # Remove trailing comma, close array
  SERVICES+=']'
  # Compose JSON for this IP
  [ $FIRST -eq 0 ] && RESULTS+=","; FIRST=0
  RESULTS+="{\"ip\":\"$IP\",\"open_ports\":[$(echo $PORTS | sed 's/,/","/g;s/^/\"/;s/$/\"/')],\"services\":$SERVICES,\"active\":true,\"scan_time\":\"$SCAN_TIME\"}"
done
RESULTS+=']'

# Output the JSON
printf '%s\n' "$RESULTS"
