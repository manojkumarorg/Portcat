from flask import Flask, jsonify, request
from db import SessionLocal
from models import ScanResult
import netsight
import datetime
import json
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This enables CORS for all routes


@app.route('/')
def root():
    return jsonify({"message": "Welcome to Flask!"})

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

@app.route('/results')
def results():
    session = SessionLocal()
    try:
        scans = session.query(ScanResult).order_by(ScanResult.created_at.desc()).all()
        results = [
            {
                "id": s.id,
                "ip": s.ip,
                "result": s.result,
                "created_at": s.created_at.isoformat()
            }
            for s in scans
        ]
        return jsonify(results)
    finally:
        session.close()

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    cidr = data.get('cidr')
    print(f"Received scan request for CIDR: {cidr}")
    if not cidr:
        return jsonify({"error": "CIDR value is required"}), 400
    try:
        # Use the new concurrent scanning function
        results = netsight.scan_cidr_concurrent(cidr)
        
        # Format results into table structure
        table_data = netsight.format_results_table(results)
        
        return jsonify({
            "cidr": cidr,
            "total_hosts": len(results),
            "active_hosts": len([r for r in results if 'error' not in r]),
            "table_data": table_data,
            "raw_results": results,
            "scan_time": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
    app.run(debug = True)
