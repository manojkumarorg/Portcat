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

@app.route('/10.1.75.0/24/scan', methods=['GET'])
def scan():
    cidr= request.host.split(':')[1] if ':' in request.host else '80'
    if not cidr:
        return jsonify({"error": "CIDR value is required"}), 400
    try:
        result = netsight.scan_host(cidr)
        return jsonify(result)
    except Exception as e:
        print(e,"line")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
    app.run(debug = True)
