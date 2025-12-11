"""
Simple CLI version of the peer for testing without GUI
Useful for Docker containers or headless testing
"""

import sys
import threading
import requests
import socket
from peer import Peer


class PeerCLI:
    """Command-line interface for peer"""
    
    def __init__(self, username, stun_server_url="http://localhost:5000", tcp_port=8888):
        self.username = username
        self.stun_server_url = stun_server_url
        self.tcp_port = tcp_port
        self.peer = None
        self.running = True
    
    def start(self):
        """Start the peer"""
        # Get local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
        
        # Register with STUN server
        print(f"Registering {self.username} with STUN server...")
        try:
            response = requests.post(
                f"{self.stun_server_url}/register",
                json={
                    "username": self.username,
                    "ip": local_ip,
                    "port": self.tcp_port
                },
                timeout=5
            )
            
            if response.status_code != 200:
                print(f"Registration failed: {response.json().get('error', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"Failed to connect to STUN server: {e}")
            return False
        
        # Initialize peer
        self.peer = Peer(self.username, self.stun_server_url, self.tcp_port)
        self.peer.set_message_callback(self.on_message)
        self.peer.set_file_callback(self.on_file)
        
        if not self.peer.start_server():
            print("Failed to start TCP server")
            return False
        
        print(f"✓ Peer {self.username} started on port {self.tcp_port}")
        return True
    
    def on_message(self, content, sender):
        """Handle received message"""
        print(f"\n[{sender}]: {content}")
        print("> ", end="", flush=True)
    
    def on_file(self, event_type, sender, message):
        """Handle file transfer"""
        if event_type == 'request':
            filename = message.get('filename')
            filesize = message.get('filesize')
            print(f"\n[{sender}] wants to send file: {filename} ({filesize} bytes)")
            print("> ", end="", flush=True)
        elif event_type == 'data':
            filename = message.get('filename')
            print(f"\n[{sender}] sent file: {filename}")
            print("> ", end="", flush=True)
    
    def list_peers(self):
        """List all online peers"""
        try:
            response = requests.get(f"{self.stun_server_url}/peers", timeout=5)
            if response.status_code == 200:
                data = response.json()
                peers = [p for p in data.get('peers', []) if p['username'] != self.username]
                
                if peers:
                    print("\nOnline Peers:")
                    for i, peer in enumerate(peers, 1):
                        print(f"  {i}. {peer['username']} ({peer['ip']}:{peer['port']})")
                else:
                    print("\nNo other peers online")
                return peers
            else:
                print("Failed to get peers list")
                return []
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def connect(self, peer_ip, peer_port, peer_username):
        """Connect to a peer"""
        print(f"Connecting to {peer_username} at {peer_ip}:{peer_port}...")
        if self.peer.connect_to_peer(peer_ip, peer_port, peer_username):
            print(f"✓ Connected to {peer_username}")
            return True
        else:
            print(f"✗ Failed to connect to {peer_username}")
            return False
    
    def send_message(self, peer_username, message):
        """Send a message to a peer"""
        if self.peer.send_message(peer_username, message):
            print(f"→ {peer_username}: {message}")
            return True
        else:
            print(f"✗ Failed to send message")
            return False
    
    def run(self):
        """Run the CLI interface"""
        if not self.start():
            return
        
        print("\nCommands:")
        print("  list          - List online peers")
        print("  connect <n>   - Connect to peer number n from list")
        print("  send <user>   - Send message to user (then type message)")
        print("  quit          - Exit")
        print("\n" + "=" * 50)
        
        while self.running:
            try:
                cmd = input("> ").strip().split()
                if not cmd:
                    continue
                
                if cmd[0] == "quit":
                    break
                elif cmd[0] == "list":
                    peers = self.list_peers()
                elif cmd[0] == "connect" and len(cmd) > 1:
                    peers = self.list_peers()
                    try:
                        idx = int(cmd[1]) - 1
                        if 0 <= idx < len(peers):
                            peer = peers[idx]
                            self.connect(peer['ip'], peer['port'], peer['username'])
                        else:
                            print("Invalid peer number")
                    except ValueError:
                        print("Invalid peer number")
                elif cmd[0] == "send" and len(cmd) > 1:
                    peer_username = cmd[1]
                    message = input("Message: ")
                    self.send_message(peer_username, message)
                else:
                    print("Unknown command")
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        if self.peer:
            self.peer.stop()
        print("\nGoodbye!")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python peer_cli.py <username> [tcp_port] [stun_url]")
        print("Example: python peer_cli.py peer1 8888 http://localhost:5000")
        sys.exit(1)
    
    username = sys.argv[1]
    tcp_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    stun_url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:5000"
    
    cli = PeerCLI(username, stun_url, tcp_port)
    cli.run()


if __name__ == '__main__':
    main()

