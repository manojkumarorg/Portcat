import subprocess
import json
import sys
import datetime
import ipaddress


def rustscan_cidr(cidr):
    result = subprocess.run(
        ['rustscan', '-a', cidr, '--ulimit', '5000', '-g'],
        capture_output=True, text=True, timeout=60  # 60 seconds
    )
    return result.stdout

def nmap_services(ip, ports):
    if not ports:
        return ''
    port_str = ','.join(map(str, ports))
    result = subprocess.run(
        ['nmap', '-sV', '-p', port_str, ip, '-oX', '-'],
        capture_output=True, text=True
    )
    return result.stdout  # XML output

def scan_host(ip, prev_port_times=None):
    open_ports = rustscan_cidr(ip).strip().split()
    now = datetime.datetime.utcnow().isoformat()
    port_times = []
    prev_port_times = prev_port_times or {}
    for port in open_ports:
        if port in prev_port_times:
            opened_at = prev_port_times[port]['opened_at']
        else:
            opened_at = now
        port_times.append({
            "port": port,
            "opened_at": opened_at,
            "last_live_check": now
        })
    nmap_xml = nmap_services(ip, open_ports)
    return {
        "ip": ip,
        "open_ports": open_ports,
        "port_times": port_times,
        "nmap_xml": nmap_xml
    }

def scan_cidr(cidr, prev_results=None):
    results = []
    prev_results = prev_results or {}
    for ip in ipaddress.IPv4Network(cidr, strict=False):
        ip_str = str(ip)
        prev_port_times = {pt['port']: pt for pt in prev_results.get(ip_str, {}).get('port_times', [])}
        result = scan_host(ip_str, prev_port_times)
        results.append(result)
    return results

# Example usage:
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CIDR provided, running test scan on 127.0.0.1/32...")
        cidr = "127.0.0.1/32"
    else:
        cidr = sys.argv[1]
    output = rustscan_cidr(cidr)
    print(output) 