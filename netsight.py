import subprocess
import sys
import ipaddress
import xml.etree.ElementTree as ET


def nmap_scan(target: str, port_range: str | None = None, timeout: int = 600) -> dict[str, list[int]]:
    """
    Run nmap on the given target (IP or CIDR) and return a dict of {ip: [open_ports]}.
    - Uses -T4 for faster timing
    - Uses -Pn to skip host discovery (scan all addresses)
    - Uses -n to disable DNS lookups (faster and avoids PTR noise)
    If port_range is None, Nmap scans its default top 1000 TCP ports.
    """
    cmd = [
        'nmap', '-T4', '-Pn', '-n',
        '-oX', '-'
    ]
    if port_range:
        cmd += ['-p', str(port_range)]
    cmd.append(target)

    try:
        print(f"Debug: Running nmap command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
        )
        print(f"Debug: Nmap stdout length: {len(result.stdout)}")
        print(f"Debug: Nmap stderr: {result.stderr}")
        return parse_nmap_xml(result.stdout)
    except Exception as e:
        print(f"Error running nmap: {e}")
        return {}


def parse_nmap_xml(xml_output: str) -> dict[str, list[int]]:
    """Parse nmap XML output and return a dict of {ip: [open_ports]}.
    Prefers IPv4 address when multiple addresses are present.
    """
    ip_ports: dict[str, list[int]] = {}
    try:
        root = ET.fromstring(xml_output)
        print(f"Debug: XML parsing - found {len(root.findall('host'))} host elements")

        for host in root.findall('host'):
            # Prefer IPv4 address if present
            addr_elem = host.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host.find('address')
            if addr_elem is None:
                continue

            ip = addr_elem.get('addr')

            status_elem = host.find('status')
            is_alive = status_elem is not None and status_elem.get('state') == 'up'

            open_ports = [
                int(port_elem.get('portid'))
                for port_elem in host.findall('.//port')
                if port_elem.find('state') is not None and port_elem.find('state').get('state') == 'open'
            ]

            print(f"Debug: Host {ip} - status: {is_alive}, open_ports: {open_ports}")

            if is_alive or len(open_ports) > 0:
                ip_ports[ip] = open_ports
                print(f"Debug: Added {ip} as alive with {len(open_ports)} open ports")
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
    return ip_ports


def scan_cidr_or_ip(target: str, port_range: str | None = None) -> list[dict]:
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

    results: list[dict] = []
    for ip in all_ips:
        ports = ip_ports.get(ip, [])
        is_alive = ip in ip_ports
        results.append({
            "ip": ip,
            "open_ports": ports,
            "is_alive": is_alive
        })
    alive_count = sum(1 for r in results if r["is_alive"])
    print(f"Scan complete: {scan_type}. Alive hosts: {alive_count}/{len(results)}.")
    return results


def main() -> None:
    if len(sys.argv) < 2:
        print("No CIDR or IP provided, running test scan on 127.0.0.1/32...")
        target = "127.0.0.1/32"
    else:
        target = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) > 2 else None
    scan_cidr_or_ip(target, port_range)


if __name__ == "__main__":
    main()
