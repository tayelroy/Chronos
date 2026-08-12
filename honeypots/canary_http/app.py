
import logging
import json
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure JSON Logging to file and stdout
log_file = "/app/logs/canary_access.json"
logger = logging.getLogger("CanaryTrap")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(file_handler)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "canary_http_hit",
        "src_ip": request.remote_addr,
        "method": request.method,
        "path": f"/{path}",
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
        "headers": dict(request.headers)
    }
    logger.info(json.dumps(log_entry))
    
    # Return fake admin login page / decoy payload
    if "admin" in path or "config" in path:
        return jsonify({"status": "error", "message": "Unauthorized access to canary resource"}), 403
    return "<html><body><h1>IIS 10.0 Server</h1></body></html>", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)