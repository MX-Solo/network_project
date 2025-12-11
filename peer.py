"""
Peer-to-Peer Communication Module
Handles TCP connections for direct P2P messaging and file transfer
"""

import socket
import threading
import json
import struct
import os
from datetime import datetime
from enum import Enum


class MessageType(Enum):
    """Message types for P2P communication"""
    TEXT = "TEXT"
    FILE_REQUEST = "FILE_REQUEST"
    FILE_DATA = "FILE_DATA"
    FILE_ACCEPT = "FILE_ACCEPT"
    FILE_REJECT = "FILE_REJECT"
    CONNECTION_REQUEST = "CONNECTION_REQUEST"
    CONNECTION_ACCEPT = "CONNECTION_ACCEPT"
    CONNECTION_REJECT = "CONNECTION_REJECT"
    DISCONNECT = "DISCONNECT"
    ERROR = "ERROR"


class Peer:
    """
    Peer class that acts as both client and server
    Handles direct TCP connections with other peers
    """
    
    def __init__(self, username, stun_server_url="http://localhost:5000", tcp_port=8888):
        self.username = username
        self.stun_server_url = stun_server_url
        self.tcp_port = tcp_port
        self.server_socket = None
        self.connections = {}  # {peer_username: socket}
        self.is_running = False
        self.message_callback = None
        self.file_callback = None
        self.connection_callback = None  # Callback for connection events
        self.server_thread = None
        self.receive_threads = {}
        
    def set_message_callback(self, callback):
        """Set callback function for received messages"""
        self.message_callback = callback
    
    def set_file_callback(self, callback):
        """Set callback function for file transfer events"""
        self.file_callback = callback
    
    def set_connection_callback(self, callback):
        """Set callback function for connection events (connect/disconnect)"""
        self.connection_callback = callback
    
    def start_server(self):
        """Start TCP server to accept incoming connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.tcp_port))
            self.server_socket.listen(10)
            self.is_running = True
            
            self.server_thread = threading.Thread(target=self._accept_connections, daemon=True)
            self.server_thread.start()
            
            print(f"✓ TCP Server started on port {self.tcp_port}")
            return True
        except Exception as e:
            print(f"✗ Failed to start server: {e}")
            return False
    
    def _accept_connections(self):
        """Accept incoming connections from other peers"""
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"✓ Incoming connection from {address[0]}:{address[1]}")
                
                # Start thread to handle this connection
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, address),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                if self.is_running:
                    print(f"✗ Error accepting connection: {e}")
    
    def _handle_connection(self, client_socket, address):
        """Handle a single connection"""
        try:
            # Set timeout for initial handshake
            client_socket.settimeout(5)
            
            # First message should be a connection request with username
            message = self._receive_message(client_socket)
            
            if message and message.get('type') == MessageType.CONNECTION_REQUEST.value:
                peer_username = message.get('username')
                
                # Auto-accept connection (can be modified to show prompt)
                accept_message = {
                    'type': MessageType.CONNECTION_ACCEPT.value,
                    'username': self.username,
                    'timestamp': datetime.now().isoformat()
                }
                self._send_message(client_socket, accept_message)
                
                # Store connection
                self.connections[peer_username] = client_socket
                
                # Remove timeout for receive loop
                client_socket.settimeout(None)
                
                # Notify about connection
                if self.connection_callback:
                    self.connection_callback('connected', peer_username)
                elif self.message_callback:
                    self.message_callback(f"System: {peer_username} connected", "system")
                
                # Start receiving messages from this peer in a separate thread
                receive_thread = threading.Thread(
                    target=self._receive_loop,
                    args=(client_socket, peer_username),
                    daemon=True
                )
                receive_thread.start()
                self.receive_threads[peer_username] = receive_thread
            else:
                client_socket.close()
        except socket.timeout:
            print(f"✗ Connection timeout from {address}")
            if client_socket:
                client_socket.close()
        except Exception as e:
            print(f"✗ Error handling connection: {e}")
            if client_socket:
                client_socket.close()
    
    def connect_to_peer(self, peer_ip, peer_port, peer_username):
        """
        Connect to another peer as a client
        Returns True if connection successful, False otherwise
        """
        try:
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            
            # Remove timeout after connection
            sock.settimeout(None)
            
            # Send connection request
            request = {
                'type': MessageType.CONNECTION_REQUEST.value,
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(sock, request)
            
            # Wait for response with timeout
            sock.settimeout(5)
            response = self._receive_message(sock)
            sock.settimeout(None)  # Remove timeout for receive loop
            
            if response and response.get('type') == MessageType.CONNECTION_ACCEPT.value:
                self.connections[peer_username] = sock
                
                # Notify about connection
                if self.connection_callback:
                    self.connection_callback('connected', peer_username)
                elif self.message_callback:
                    self.message_callback(f"System: Connected to {peer_username}", "system")
                
                # Start receiving messages in a separate thread
                receive_thread = threading.Thread(
                    target=self._receive_loop,
                    args=(sock, peer_username),
                    daemon=True
                )
                receive_thread.start()
                self.receive_threads[peer_username] = receive_thread
                return True
            else:
                sock.close()
                if self.message_callback:
                    self.message_callback(f"System: Connection rejected by {peer_username}", "system")
                return False
                
        except socket.timeout:
            if self.message_callback:
                self.message_callback(f"System: Connection timeout to {peer_username}", "system")
            return False
        except Exception as e:
            if self.message_callback:
                self.message_callback(f"System: Failed to connect to {peer_username}: {str(e)}", "system")
            return False
    
    def _receive_loop(self, sock, peer_username):
        """Continuously receive messages from a peer"""
        # Remove timeout for blocking receive
        sock.settimeout(None)
        
        while self.is_running:
            try:
                message = self._receive_message(sock)
                
                if not message:
                    break
                
                msg_type = message.get('type')
                
                if msg_type == MessageType.TEXT.value:
                    if self.message_callback:
                        self.message_callback(
                            message.get('content', ''),
                            peer_username
                        )
                
                elif msg_type == MessageType.FILE_REQUEST.value:
                    if self.file_callback:
                        self.file_callback('request', peer_username, message)
                
                elif msg_type == MessageType.FILE_DATA.value:
                    if self.file_callback:
                        self.file_callback('data', peer_username, message)
                
                elif msg_type == MessageType.DISCONNECT.value:
                    if self.connection_callback:
                        self.connection_callback('disconnected', peer_username)
                    elif self.message_callback:
                        self.message_callback(f"System: {peer_username} disconnected", "system")
                    break
                
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                # Connection lost
                if self.connection_callback:
                    self.connection_callback('disconnected', peer_username)
                elif self.message_callback:
                    self.message_callback(f"System: Connection lost with {peer_username}", "system")
                break
            except Exception as e:
                print(f"✗ Error receiving from {peer_username}: {e}")
                if self.connection_callback:
                    self.connection_callback('disconnected', peer_username)
                elif self.message_callback:
                    self.message_callback(f"System: Error receiving from {peer_username}: {str(e)}", "system")
                break
        
        # Clean up connection
        if peer_username in self.connections:
            del self.connections[peer_username]
        if peer_username in self.receive_threads:
            del self.receive_threads[peer_username]
        try:
            sock.close()
        except:
            pass
    
    def send_message(self, peer_username, content):
        """Send a text message to a peer"""
        if peer_username not in self.connections:
            if self.message_callback:
                self.message_callback(f"System: Not connected to {peer_username}", "system")
            return False
        
        try:
            message = {
                'type': MessageType.TEXT.value,
                'content': content,
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(self.connections[peer_username], message)
            return True
        except Exception as e:
            if self.message_callback:
                self.message_callback(f"System: Failed to send message: {str(e)}", "system")
            return False
    
    def send_file(self, peer_username, file_path):
        """Send a file to a peer"""
        if peer_username not in self.connections:
            if self.message_callback:
                self.message_callback(f"System: Not connected to {peer_username}", "system")
            return False
        
        if not os.path.exists(file_path):
            if self.message_callback:
                self.message_callback(f"System: File not found: {file_path}", "system")
            return False
        
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Send file request
            request = {
                'type': MessageType.FILE_REQUEST.value,
                'filename': file_name,
                'filesize': file_size,
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(self.connections[peer_username], request)
            
            # Wait for acceptance (in real implementation, this would be async)
            # For simplicity, we'll send the file immediately
            # In GUI, this would wait for user confirmation
            
            # Send file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_message = {
                'type': MessageType.FILE_DATA.value,
                'filename': file_name,
                'filesize': file_size,
                'data': file_data.hex(),  # Convert to hex string for JSON
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(self.connections[peer_username], file_message)
            
            if self.message_callback:
                self.message_callback(f"System: File '{file_name}' sent to {peer_username}", "system")
            return True
            
        except Exception as e:
            if self.message_callback:
                self.message_callback(f"System: Failed to send file: {str(e)}", "system")
            return False
    
    def _send_message(self, sock, message):
        """Send a JSON message over socket"""
        try:
            data = json.dumps(message).encode('utf-8')
            # Send length first, then data
            length = struct.pack('>I', len(data))
            sock.sendall(length + data)
        except Exception as e:
            raise Exception(f"Send error: {e}")
    
    def _receive_message(self, sock):
        """Receive a JSON message from socket"""
        try:
            # Receive length
            length_data = self._recv_all(sock, 4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Receive data
            data = self._recv_all(sock, length)
            if not data:
                return None
            
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            raise Exception(f"Receive error: {e}")
    
    def _recv_all(self, sock, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def disconnect_from_peer(self, peer_username):
        """Disconnect from a specific peer"""
        if peer_username not in self.connections:
            # Already disconnected, just notify
            if self.connection_callback:
                self.connection_callback('disconnected', peer_username)
            return
        
        try:
            disconnect_msg = {
                'type': MessageType.DISCONNECT.value,
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(self.connections[peer_username], disconnect_msg)
            self.connections[peer_username].close()
        except:
            pass
        
        # Remove from connections
        if peer_username in self.connections:
            del self.connections[peer_username]
        
        # Notify about disconnection
        if self.connection_callback:
            self.connection_callback('disconnected', peer_username)
    
    def stop(self):
        """Stop the peer and close all connections"""
        self.is_running = False
        
        # Close all connections
        for peer_username in list(self.connections.keys()):
            self.disconnect_from_peer(peer_username)
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("✓ Peer stopped")

