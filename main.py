from flask import Flask, jsonify, request
import netsight
import datetime
import json
from flask_cors import CORS

app = Flask(__name__)
# Configure CORS for development
CORS(app)

# In-memory storage for scan results (replace with database in production)
scan_results = []

@app.route('/')
def root():
    return jsonify({"message": "Welcome to Flask!"})

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

@app.route('/results')
def results():
    return jsonify(scan_results)

# Simple authentication endpoints for hardcoded credentials
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username == "iQube" and password == "iQube@#2025":
        return jsonify({"success": True, "user": {"username": "iQube"}})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/user')
def current_user():
    # For hardcoded auth, just return the user info
    return jsonify({"username": "iQube"})

@app.route('/logout')
def logout():
    return jsonify({"message": "Logged out successfully"})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')  # Changed from 'cidr' to 'target' for clarity
    port_range = data.get('port_range')
    
    print(f"Received scan request for target: {target}, port_range: {port_range}")
    if not target:
        return jsonify({"error": "Target (IP or CIDR) is required"}), 400
    
    try:
        # Run the scan using our optimized netsight module
        scan_results_data = netsight.scan_cidr_or_ip(target, port_range)
        
        # Store scan metadata
        scan_result = {
            "target": target,
            "port_range": port_range,
            "scan_time": datetime.datetime.utcnow().isoformat(),
            "status": "completed",
            "results": scan_results_data
        }
        scan_results.append(scan_result)
        
        return jsonify({
            "target": target,
            "port_range": port_range,
            "scan_time": datetime.datetime.utcnow().isoformat(),
            "status": "completed",
            "total_hosts": len(scan_results_data),
            "hosts_with_open_ports": len([r for r in scan_results_data if r["is_alive"]]),
            "results": scan_results_data
        })
    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": str(e)}), 500




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
