import subprocess
import sys
import ipaddress
import xml.etree.ElementTree as ET

def nmap_scan(target, port_range=None, timeout=300):
    """
    Run nmap on the given target (IP or CIDR) and return a dict of {ip: [open_ports]}.
    Always use -T4 for faster scanning. If port_range is None, scan Nmap's default top 1000 ports.
    """
    if port_range:
        cmd = ['nmap', '-T4', '-oX', '-']
        cmd += ['-p', str(port_range)]
    else:
        cmd = ['nmap', '-T4', '-oX', '-']  # Default: top 1000 ports
    cmd.append(target)
    try:
        print(f"Debug: Running nmap command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace'
        )
        print(f"Debug: Nmap stdout length: {len(result.stdout)}")
        print(f"Debug: Nmap stderr: {result.stderr}")
        return parse_nmap_xml(result.stdout)
    except Exception as e:
        print(f"Error running nmap: {e}")
        return {}

def parse_nmap_xml(xml_output):
    """
    Parse nmap XML output and return a dict of {ip: [open_ports]}.
    """
    ip_ports = {}
    try:
        root = ET.fromstring(xml_output)
        print(f"Debug: XML parsing - found {len(root.findall('host'))} host elements")
        
        for host in root.findall('host'):
            addr_elem = host.find('address')
            if addr_elem is not None:
                ip = addr_elem.get('addr')
                # Check if host is alive (has status 'up' or has open ports)
                status_elem = host.find('status')
                is_alive = False
                if status_elem is not None:
                    is_alive = status_elem.get('state') == 'up'
                
                # Get open ports
                open_ports = [
                    int(port_elem.get('portid'))
                    for port_elem in host.findall('.//port')
                    if port_elem.find('state') is not None and port_elem.find('state').get('state') == 'open'
                ]
                
                print(f"Debug: Host {ip} - status: {is_alive}, open_ports: {open_ports}")
                
                # Consider host alive if status is 'up' OR if it has open ports
                # If no status element, consider alive if it has open ports
                if is_alive or len(open_ports) > 0:
                    ip_ports[ip] = open_ports
                    print(f"Debug: Added {ip} as alive with {len(open_ports)} open ports")
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
    return ip_ports

def scan_cidr_or_ip(target, port_range=None):
    """
    Scan a CIDR or single IP for open ports and return the results as a list of dicts.
    Each dict contains: ip, open_ports, is_alive.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        all_ips = [str(ip) for ip in network.hosts()]
        scan_type = f"subnet {target} with {len(all_ips)} hosts"
    except ValueError:
        all_ips = [target]
        scan_type = f"single IP {target}"

    print(f"Debug: Starting scan for {scan_type}")
    ip_ports = nmap_scan(target, port_range)
    print(f"Debug: nmap found {len(ip_ports)} hosts with entries")
    if ip_ports:
        print(f"Debug: Sample hosts found: {list(ip_ports.keys())[:5]}")
    
    results = []
    for ip in all_ips:
        ports = ip_ports.get(ip, [])
        # A host is considered alive if it was detected by nmap (has an entry in ip_ports)
        is_alive = ip in ip_ports
        results.append({
            "ip": ip,
            "open_ports": ports,
            "is_alive": is_alive
        })
    alive_count = sum(1 for r in results if r["is_alive"])
    print(f"Scan complete: {scan_type}. Alive hosts: {alive_count}/{len(results)}.")
    return results

def main():
    if len(sys.argv) < 2:
        print("No CIDR or IP provided, running test scan on 127.0.0.1/32...")
        target = "127.0.0.1/32"
    else:
        target = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) > 2 else None
    scan_cidr_or_ip(target, port_range)

if __name__ == "__main__":
    main() 