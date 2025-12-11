"""
STUN Server - Central server for managing peer addresses
Uses HTTP protocol and Redis for caching peer information
"""

from flask import Flask, request, jsonify
import redis
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Redis connection
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    redis_client.ping()
    print(f"✓ Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.ConnectionError:
    print(f"✗ Failed to connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
    print("  Make sure Redis is running or use Docker Compose")
    redis_client = None

# Peer timeout (30 seconds)
PEER_TIMEOUT = 30


def get_peer_key(username):
    """Generate Redis key for peer"""
    return f"peer:{username}"


def is_peer_online(username):
    """Check if peer is still online"""
    if not redis_client:
        return False
    
    peer_key = get_peer_key(username)
    peer_data = redis_client.get(peer_key)
    
    if not peer_data:
        return False
    
    try:
        peer_info = json.loads(peer_data)
        last_seen = datetime.fromisoformat(peer_info.get('last_seen', ''))
        if datetime.now() - last_seen > timedelta(seconds=PEER_TIMEOUT):
            redis_client.delete(peer_key)
            return False
        return True
    except:
        return False


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new peer or update existing peer information
    POST /register
    Body: {
        "username": "peer1",
        "ip": "192.168.1.100",
        "port": 8888
    }
    """
    if not redis_client:
        return jsonify({"error": "Redis not available"}), 503
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        username = data.get('username')
        ip = data.get('ip')
        port = data.get('port')
        
        if not all([username, ip, port]):
            return jsonify({"error": "Missing required fields: username, ip, port"}), 400
        
        # Get client IP if not provided
        if ip == 'auto':
            ip = request.remote_addr
        
        # Validate port
        try:
            port = int(port)
            if port < 1024 or port > 65535:
                return jsonify({"error": "Port must be between 1024 and 65535"}), 400
        except ValueError:
            return jsonify({"error": "Port must be a number"}), 400
        
        # Check if username already exists
        peer_key = get_peer_key(username)
        existing_peer = redis_client.get(peer_key)
        
        if existing_peer:
            # Update existing peer
            peer_info = json.loads(existing_peer)
            if peer_info.get('ip') != ip or peer_info.get('port') != port:
                print(f"Updated peer {username}: {peer_info.get('ip')}:{peer_info.get('port')} -> {ip}:{port}")
        else:
            print(f"New peer registered: {username} at {ip}:{port}")
        
        # Store peer information
        peer_data = {
            "username": username,
            "ip": ip,
            "port": port,
            "last_seen": datetime.now().isoformat(),
            "registered_at": datetime.now().isoformat()
        }
        
        redis_client.setex(
            peer_key,
            PEER_TIMEOUT,
            json.dumps(peer_data)
        )
        
        return jsonify({
            "status": "success",
            "message": "Peer registered successfully",
            "peer": peer_data
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/peers', methods=['GET'])
def get_peers():
    """
    Get list of all online peers
    GET /peers
    Returns: {
        "peers": [
            {
                "username": "peer1",
                "ip": "192.168.1.100",
                "port": 8888
            },
            ...
        ]
    }
    """
    if not redis_client:
        return jsonify({"error": "Redis not available"}), 503
    
    try:
        online_peers = []
        
        # Scan all peer keys
        for key in redis_client.scan_iter(match="peer:*"):
            username = key.split(":")[1]
            
            if is_peer_online(username):
                peer_data = json.loads(redis_client.get(key))
                online_peers.append({
                    "username": peer_data["username"],
                    "ip": peer_data["ip"],
                    "port": peer_data["port"]
                })
        
        return jsonify({
            "status": "success",
            "count": len(online_peers),
            "peers": online_peers
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/peerinfo', methods=['GET'])
def get_peer_info():
    """
    Get information about a specific peer
    GET /peerinfo?username=peer1
    Returns: {
        "username": "peer1",
        "ip": "192.168.1.100",
        "port": 8888
    }
    """
    if not redis_client:
        return jsonify({"error": "Redis not available"}), 503
    
    try:
        username = request.args.get('username')
        
        if not username:
            return jsonify({"error": "Username parameter required"}), 400
        
        peer_key = get_peer_key(username)
        peer_data = redis_client.get(peer_key)
        
        if not peer_data:
            return jsonify({"error": "Peer not found"}), 404
        
        if not is_peer_online(username):
            return jsonify({"error": "Peer is offline"}), 404
        
        peer_info = json.loads(peer_data)
        
        return jsonify({
            "status": "success",
            "peer": {
                "username": peer_info["username"],
                "ip": peer_info["ip"],
                "port": peer_info["port"]
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    redis_status = "connected" if redis_client and redis_client.ping() else "disconnected"
    
    return jsonify({
        "status": "ok",
        "redis": redis_status
    }), 200


if __name__ == '__main__':
    print("=" * 50)
    print("STUN Server Starting...")
    print("=" * 50)
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    print(f"Endpoints:")
    print(f"  POST   /register  - Register a peer")
    print(f"  GET    /peers      - Get all online peers")
    print(f"  GET    /peerinfo   - Get peer information")
    print(f"  GET    /health     - Health check")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=True)

