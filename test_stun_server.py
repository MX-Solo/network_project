"""
Test script for STUN Server endpoints
Run this after starting the STUN server to verify functionality
"""

import requests
import time
import json

STUN_SERVER_URL = "http://localhost:5000"


def test_health():
    """Test health endpoint"""
    print("Testing /health endpoint...")
    try:
        response = requests.get(f"{STUN_SERVER_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_register(username, ip, port):
    """Test peer registration"""
    print(f"\nTesting /register endpoint for {username}...")
    try:
        response = requests.post(
            f"{STUN_SERVER_URL}/register",
            json={"username": username, "ip": ip, "port": port}
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_get_peers():
    """Test getting all peers"""
    print("\nTesting /peers endpoint...")
    try:
        response = requests.get(f"{STUN_SERVER_URL}/peers")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_get_peer_info(username):
    """Test getting specific peer info"""
    print(f"\nTesting /peerinfo endpoint for {username}...")
    try:
        response = requests.get(f"{STUN_SERVER_URL}/peerinfo?username={username}")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 50)
    print("STUN Server Test Suite")
    print("=" * 50)
    
    # Test health
    if not test_health():
        print("\n✗ Health check failed. Is the STUN server running?")
        return
    
    # Register test peers
    print("\n" + "=" * 50)
    print("Registering Test Peers")
    print("=" * 50)
    
    test_register("test_peer1", "192.168.1.100", 8888)
    time.sleep(0.5)
    test_register("test_peer2", "192.168.1.101", 8889)
    time.sleep(0.5)
    test_register("test_peer3", "192.168.1.102", 8890)
    
    # Get all peers
    print("\n" + "=" * 50)
    print("Testing Peer Discovery")
    print("=" * 50)
    test_get_peers()
    
    # Get specific peer info
    print("\n" + "=" * 50)
    print("Testing Peer Info Retrieval")
    print("=" * 50)
    test_get_peer_info("test_peer1")
    test_get_peer_info("nonexistent_peer")
    
    print("\n" + "=" * 50)
    print("Test Suite Complete")
    print("=" * 50)


if __name__ == '__main__':
    main()

