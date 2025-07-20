#!/usr/bin/env python3
import subprocess
import json
# Removed unused imports and fixed import errors
from netsight.scan import scan_host, scan_cidr

def test_single_ip():
    """Test scanning a single IP address"""
    print("=== Testing Single IP Scan ===")
    ip = "172.31.67.68"
    
    try:
        result = scan_host(ip)
        print(f"Scan result for {ip}:")
        print(json.dumps(result, indent=2))
        return result
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return None

def test_cidr_scan():
    """Test scanning a CIDR range"""
    print("\n=== Testing CIDR Scan ===")
    cidr = "172.31.67.68/32"  # Single IP as CIDR
    
    try:
        results = scan_cidr(cidr)
        print(f"Scan results for {cidr}:")
        print(json.dumps(results, indent=2))
        return results
    except Exception as e:
        print(f"Error scanning {cidr}: {e}")
        return None

def test_rustscan_directly():
    """Test RustScan directly to see raw output"""
    print("\n=== Testing RustScan Directly ===")
    ip = "172.31.67.68"
    
    try:
        result = subprocess.run(
            ['rustscan', '-a', ip, '--ulimit', '5000', '-g'],
            capture_output=True, text=True, timeout=30
        )
        print(f"RustScan raw output for {ip}:")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return code: {result.returncode}")
        return result
    except subprocess.TimeoutExpired:
        print("RustScan timed out")
        return None
    except FileNotFoundError:
        print("RustScan not found. Please install it first.")
        return None
    except Exception as e:
        print(f"Error running RustScan: {e}")
        return None

def test_nmap_directly():
    """Test Nmap directly on specific ports"""
    print("\n=== Testing Nmap Directly ===")
    ip = "172.31.67.68"
    ports = "22,80,443,3000,3001,3128"  # Common ports
    
    try:
        result = subprocess.run(
            ['nmap', '-sV', '-p', ports, ip],
            capture_output=True, text=True, timeout=60
        )
        print(f"Nmap output for {ip} on ports {ports}:")
        print(result.stdout)
        return result
    except subprocess.TimeoutExpired:
        print("Nmap timed out")
        return None
    except FileNotFoundError:
        print("Nmap not found. Please install it first.")
        return None
    except Exception as e:
        print(f"Error running Nmap: {e}")
        return None

def main():
    """Run all tests"""
    print("Starting local scan tests for IP: 172.31.67.68")
    print("=" * 50)
    
    # Test 1: Direct RustScan
    rustscan_result = test_rustscan_directly()
    
    # Test 2: Direct Nmap
    nmap_result = test_nmap_directly()
    
    # Test 3: Single IP scan using netsight
    single_result = test_single_ip()
    
    # Test 4: CIDR scan using netsight
    cidr_result = test_cidr_scan()
    
    print("\n" + "=" * 50)
    print("TEST SUMMARY:")
    print(f"RustScan: {'✅ Success' if rustscan_result else '❌ Failed'}")
    print(f"Nmap: {'✅ Success' if nmap_result else '❌ Failed'}")
    print(f"Single IP Scan: {'✅ Success' if single_result else '❌ Failed'}")
    print(f"CIDR Scan: {'✅ Success' if cidr_result else '❌ Failed'}")

if __name__ == "__main__":
    main() 