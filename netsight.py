import subprocess
import json
import sys
import datetime
import ipaddress
import asyncio
import concurrent.futures
import xml.etree.ElementTree as ET
import threading
from typing import Dict, List, Any


def rustscan_cidr(cidr):
    """Run RustScan to discover open ports for a CIDR range"""
    print(f"Starting RustScan for CIDR: {cidr}")
    try:
        result = subprocess.run(
            ['rustscan', '-a', cidr, '--ulimit', '5000', '-g'],
            capture_output=True, text=True, timeout=300  # 300 seconds (5 minutes)
        )
        print(f"RustScan completed for {cidr}. Return code: {result.returncode}")
        if result.stderr:
            print(f"RustScan stderr: {result.stderr}")
        
        # Parse RustScan output to extract IP -> [ports] format
        lines = result.stdout.strip().split('\n')
        ip_ports = {}
        
        for line in lines:
            if ' -> ' in line:
                # Format: "127.0.0.1 -> [22,3000,3001,3128,3306,33856,39357]"
                parts = line.split(' -> ')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    ports_str = parts[1].strip()
                    # Remove brackets and split by comma
                    if ports_str.startswith('[') and ports_str.endswith(']'):
                        ports_str = ports_str[1:-1]  # Remove [ and ]
                        if ports_str:
                            ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                            ip_ports[ip] = ports
            elif ':' in line and ' -> ' not in line:
                # Fallback for IP:ports format
                parts = line.split(':')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    ports_str = parts[1].strip()
                    if ports_str:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                        ip_ports[ip] = ports
        
        return ip_ports
    except subprocess.TimeoutExpired:
        print(f"RustScan timed out for CIDR: {cidr}")
        raise
    except Exception as e:
        print(f"RustScan error for CIDR {cidr}: {str(e)}")
        raise

def nmap_services(ip, ports):
    """Run Nmap to detect services and OS for specific IP and ports"""
    if not ports:
        return {'services': [], 'os_info': None}
    
    port_str = ','.join(map(str, ports))
    print(f"Starting Nmap scan for IP: {ip}, ports: {port_str}")
    
    try:
        # Run Nmap with service detection and OS detection
        result = subprocess.run(
            ['nmap', '-sV', '-O', '-p', port_str, ip, '-oX', '-'],
            capture_output=True, text=True, timeout=120  # 2 minutes timeout for nmap
        )
        print(f"Nmap completed for {ip}. Return code: {result.returncode}")
        if result.stderr:
            print(f"Nmap stderr: {result.stderr}")
        
        return parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"Nmap timed out for IP: {ip}")
        return {'services': [], 'os_info': None}
    except Exception as e:
        print(f"Nmap error for IP {ip}: {str(e)}")
        return {'services': [], 'os_info': None}

def parse_nmap_xml(xml_output):
    """Parse Nmap XML output to extract services and OS information"""
    try:
        root = ET.fromstring(xml_output)
        services = []
        os_info = None
        
        # Extract OS information
        os_elem = root.find('.//osmatch')
        if os_elem is not None:
            os_info = {
                'name': os_elem.get('name', 'Unknown'),
                'accuracy': os_elem.get('accuracy', 'Unknown'),
                'line': os_elem.get('line', 'Unknown')
            }
        
        # Extract service information
        for port_elem in root.findall('.//port'):
            port_id = port_elem.get('portid')
            protocol = port_elem.get('protocol')
            state_elem = port_elem.find('state')
            service_elem = port_elem.find('service')
            
            if state_elem is not None and state_elem.get('state') == 'open':
                service_info = {
                    'port': port_id,
                    'protocol': protocol,
                    'state': 'open',
                    'service': service_elem.get('name', 'unknown') if service_elem is not None else 'unknown',
                    'version': service_elem.get('version', '') if service_elem is not None else '',
                    'product': service_elem.get('product', '') if service_elem is not None else ''
                }
                services.append(service_info)
        
        return {'services': services, 'os_info': os_info}
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
        return {'services': [], 'os_info': None}

def scan_host_concurrent(ip, ports, prev_port_times=None):
    """Scan a single host with concurrent port discovery and service detection"""
    now = datetime.datetime.utcnow().isoformat()
    prev_port_times = prev_port_times or {}
    
    # Track port timing
    port_times = []
    for port in ports:
        if port in prev_port_times:
            opened_at = prev_port_times[port]['opened_at']
        else:
            opened_at = now
        port_times.append({
            "port": port,
            "opened_at": opened_at,
            "last_live_check": now
        })
    
    # Run Nmap scan for services and OS detection
    nmap_result = nmap_services(ip, ports)
    
    return {
        "ip": ip,
        "open_ports": ports,
        "port_times": port_times,
        "services": nmap_result['services'],
        "os_info": nmap_result['os_info'],
        "scan_time": now
    }

def scan_cidr_concurrent(cidr, prev_results=None):
    """Scan a CIDR range with concurrent processing"""
    print(f"Starting concurrent scan for CIDR: {cidr}")
    
    # First, run RustScan to discover all open ports across the CIDR
    ip_ports = rustscan_cidr(cidr)
    print(f"RustScan discovered {len(ip_ports)} hosts with open ports")
    
    if not ip_ports:
        print("No hosts with open ports found")
        return []
    
    # Process each IP concurrently
    results = []
    prev_results = prev_results or {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all scan tasks
        future_to_ip = {}
        for ip, ports in ip_ports.items():
            prev_port_times = {pt['port']: pt for pt in prev_results.get(ip, {}).get('port_times', [])}
            future = executor.submit(scan_host_concurrent, ip, ports, prev_port_times)
            future_to_ip[future] = ip
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                print(f"Completed scan for {ip}")
            except Exception as e:
                print(f"Error scanning {ip}: {e}")
                # Add error result
                results.append({
                    "ip": ip,
                    "error": str(e),
                    "scan_time": datetime.datetime.utcnow().isoformat()
                })
    
    return results

def format_results_table(results):
    """Format scan results into a structured table format"""
    table_data = []
    
    for result in results:
        if 'error' in result:
            table_data.append({
                'ip': result['ip'],
                'ports': 'Error',
                'services': 'Error',
                'os_detection': 'Error',
                'active_time': 'Error',
                'status': 'Failed'
            })
            continue
        
        ip = result['ip']
        ports = result.get('open_ports', [])
        services = result.get('services', [])
        os_info = result.get('os_info', {})
        port_times = result.get('port_times', [])
        
        # Format ports
        ports_str = ', '.join(ports) if ports else 'None'
        
        # Format services
        service_list = []
        for service in services:
            service_str = f"{service['port']}/{service['protocol']} ({service['service']}"
            if service.get('product'):
                service_str += f" - {service['product']}"
            if service.get('version'):
                service_str += f" {service['version']}"
            service_str += ")"
            service_list.append(service_str)
        services_str = '; '.join(service_list) if service_list else 'None'
        
        # Format OS detection
        os_str = 'Unknown'
        if os_info and os_info.get('name'):
            os_str = f"{os_info['name']} (Accuracy: {os_info.get('accuracy', 'Unknown')}%)"
        
        # Format active time
        active_time = 'Unknown'
        if port_times:
            latest_time = max(pt['last_live_check'] for pt in port_times)
            active_time = latest_time
        
        table_data.append({
            'ip': ip,
            'ports': ports_str,
            'services': services_str,
            'os_detection': os_str,
            'active_time': active_time,
            'status': 'Active'
        })
    
    return table_data

# Example usage:
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CIDR provided, running test scan on 127.0.0.1/32...")
        cidr = "127.0.0.1/32"
    else:
        cidr = sys.argv[1]
    output = rustscan_cidr(cidr)
    print(output) 