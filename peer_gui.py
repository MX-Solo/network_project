"""
GUI Application for P2P Chat System
Provides a graphical interface for peer-to-peer communication
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import socket
from datetime import datetime
from peer import Peer


class PeerChatGUI:
    """Main GUI application for P2P chat"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Chat System")
        self.root.geometry("900x700")
        
        # Configuration
        self.stun_server_url = "http://localhost:5000"
        self.username = None
        self.tcp_port = 8888
        self.peer = None
        self.connected_peers = {}
        
        # Setup UI
        self.setup_ui()
        
        # Auto-refresh peers list
        self.refresh_peers_loop()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Login section
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="10")
        login_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5)
        self.username_entry = ttk.Entry(login_frame, width=20)
        self.username_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(login_frame, text="TCP Port:").grid(row=0, column=2, padx=5)
        self.port_entry = ttk.Entry(login_frame, width=10)
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=0, column=3, padx=5)
        
        self.login_button = ttk.Button(login_frame, text="Login", command=self.login)
        self.login_button.grid(row=0, column=4, padx=5)
        
        self.logout_button = ttk.Button(login_frame, text="Logout", command=self.logout, state=tk.DISABLED)
        self.logout_button.grid(row=0, column=5, padx=5)
        
        # Status label
        self.status_label = ttk.Label(login_frame, text="Status: Not connected", foreground="red")
        self.status_label.grid(row=1, column=0, columnspan=6, pady=(5, 0))
        
        # Left panel - Peers list
        peers_frame = ttk.LabelFrame(main_frame, text="Online Peers", padding="10")
        peers_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        peers_frame.rowconfigure(1, weight=1)
        
        # Refresh button
        refresh_button = ttk.Button(peers_frame, text="Refresh", command=self.refresh_peers)
        refresh_button.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # Peers listbox
        peers_list_frame = ttk.Frame(peers_frame)
        peers_list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        peers_list_frame.columnconfigure(0, weight=1)
        peers_list_frame.rowconfigure(0, weight=1)
        
        self.peers_listbox = tk.Listbox(peers_list_frame, height=15)
        self.peers_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        peers_scrollbar = ttk.Scrollbar(peers_list_frame, orient=tk.VERTICAL, command=self.peers_listbox.yview)
        peers_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.peers_listbox.configure(yscrollcommand=peers_scrollbar.set)
        
        # Connect button
        connect_button = ttk.Button(peers_frame, text="Connect to Selected", command=self.connect_to_selected_peer)
        connect_button.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Right panel - Chat
        chat_frame = ttk.LabelFrame(main_frame, text="Chat", padding="10")
        chat_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=20, state=tk.DISABLED, wrap=tk.WORD)
        self.chat_display.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Chat input
        ttk.Label(chat_frame, text="Message:").grid(row=1, column=0, sticky=tk.W)
        self.message_entry = ttk.Entry(chat_frame)
        self.message_entry.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # Buttons frame
        buttons_frame = ttk.Frame(chat_frame)
        buttons_frame.grid(row=2, column=1, padx=(5, 0))
        
        send_button = ttk.Button(buttons_frame, text="Send", command=self.send_message)
        send_button.pack(side=tk.LEFT, padx=2)
        
        file_button = ttk.Button(buttons_frame, text="Send File", command=self.send_file)
        file_button.pack(side=tk.LEFT, padx=2)
        
        # Connected peers frame
        connected_frame = ttk.LabelFrame(main_frame, text="Connected Peers", padding="10")
        connected_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.connected_listbox = tk.Listbox(connected_frame, height=3)
        self.connected_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        disconnect_button = ttk.Button(connected_frame, text="Disconnect Selected", command=self.disconnect_selected)
        disconnect_button.pack(side=tk.LEFT, padx=5)
    
    def login(self):
        """Login to STUN server and start peer"""
        username = self.username_entry.get().strip()
        port_str = self.port_entry.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return
        
        try:
            self.tcp_port = int(port_str)
            if self.tcp_port < 1024 or self.tcp_port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number (1024-65535)")
            return
        
        self.username = username
        
        # Get local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
        
        # Register with STUN server
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
            
            if response.status_code == 200:
                # Initialize peer
                self.peer = Peer(self.username, self.stun_server_url, self.tcp_port)
                self.peer.set_message_callback(self.on_message_received)
                self.peer.set_file_callback(self.on_file_event)
                
                if self.peer.start_server():
                    self.status_label.config(text=f"Status: Connected as {self.username}", foreground="green")
                    self.login_button.config(state=tk.DISABLED)
                    self.logout_button.config(state=tk.NORMAL)
                    self.username_entry.config(state=tk.DISABLED)
                    self.port_entry.config(state=tk.DISABLED)
                    self.add_chat_message("System", f"Logged in as {self.username}")
                    self.refresh_peers()
                else:
                    messagebox.showerror("Error", "Failed to start TCP server")
            else:
                messagebox.showerror("Error", f"Registration failed: {response.json().get('error', 'Unknown error')}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to STUN server: {str(e)}")
    
    def logout(self):
        """Logout and stop peer"""
        if self.peer:
            self.peer.stop()
            self.peer = None
        
        self.status_label.config(text="Status: Not connected", foreground="red")
        self.login_button.config(state=tk.NORMAL)
        self.logout_button.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.username = None
        self.connected_peers = {}
        self.connected_listbox.delete(0, tk.END)
        self.add_chat_message("System", "Logged out")
    
    def refresh_peers(self):
        """Refresh the list of online peers"""
        if not self.username:
            return
        
        try:
            response = requests.get(f"{self.stun_server_url}/peers", timeout=5)
            if response.status_code == 200:
                data = response.json()
                peers = data.get('peers', [])
                
                # Filter out self
                peers = [p for p in peers if p['username'] != self.username]
                
                # Update listbox
                self.peers_listbox.delete(0, tk.END)
                for peer in peers:
                    self.peers_listbox.insert(tk.END, f"{peer['username']} ({peer['ip']}:{peer['port']})")
        except Exception as e:
            print(f"Error refreshing peers: {e}")
    
    def refresh_peers_loop(self):
        """Auto-refresh peers list every 5 seconds"""
        if self.username:
            self.refresh_peers()
        self.root.after(5000, self.refresh_peers_loop)
    
    def connect_to_selected_peer(self):
        """Connect to the selected peer"""
        if not self.peer:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        selection = self.peers_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a peer")
            return
        
        peer_str = self.peers_listbox.get(selection[0])
        # Parse "username (ip:port)"
        parts = peer_str.split(' (')
        if len(parts) != 2:
            return
        
        username = parts[0]
        ip_port = parts[1].rstrip(')')
        ip, port = ip_port.split(':')
        port = int(port)
        
        if username in self.connected_peers:
            messagebox.showinfo("Info", f"Already connected to {username}")
            return
        
        # Connect in a separate thread
        def connect_thread():
            if self.peer.connect_to_peer(ip, port, username):
                self.connected_peers[username] = {'ip': ip, 'port': port}
                self.root.after(0, lambda: self.connected_listbox.insert(tk.END, username))
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def send_message(self):
        """Send a message to connected peers"""
        if not self.peer:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Get selected connected peer
        selection = self.connected_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a connected peer")
            return
        
        peer_username = self.connected_listbox.get(selection[0])
        
        if self.peer.send_message(peer_username, message):
            self.add_chat_message(f"You → {peer_username}", message)
            self.message_entry.delete(0, tk.END)
    
    def send_file(self):
        """Send a file to selected peer"""
        if not self.peer:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        selection = self.connected_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a connected peer")
            return
        
        peer_username = self.connected_listbox.get(selection[0])
        
        file_path = filedialog.askopenfilename(title="Select file to send")
        if file_path:
            def send_thread():
                self.peer.send_file(peer_username, file_path)
            
            threading.Thread(target=send_thread, daemon=True).start()
    
    def disconnect_selected(self):
        """Disconnect from selected peer"""
        if not self.peer:
            return
        
        selection = self.connected_listbox.curselection()
        if not selection:
            return
        
        peer_username = self.connected_listbox.get(selection[0])
        self.peer.disconnect_from_peer(peer_username)
        
        if peer_username in self.connected_peers:
            del self.connected_peers[peer_username]
        
        self.connected_listbox.delete(selection[0])
        self.add_chat_message("System", f"Disconnected from {peer_username}")
    
    def on_message_received(self, content, sender):
        """Callback for received messages"""
        self.root.after(0, lambda: self.add_chat_message(sender, content))
    
    def on_file_event(self, event_type, sender, message):
        """Callback for file transfer events"""
        if event_type == 'request':
            filename = message.get('filename')
            filesize = message.get('filesize')
            
            result = messagebox.askyesno(
                "File Transfer Request",
                f"{sender} wants to send you a file:\n\n"
                f"Filename: {filename}\n"
                f"Size: {filesize / 1024:.2f} KB\n\n"
                f"Do you want to accept?"
            )
            
            if result:
                # Save file
                file_path = filedialog.asksaveasfilename(
                    title="Save file as",
                    initialfile=filename
                )
                if file_path:
                    # In a real implementation, we'd wait for file data
                    # For now, we'll just acknowledge
                    self.add_chat_message("System", f"File transfer from {sender} accepted")
        
        elif event_type == 'data':
            filename = message.get('filename')
            file_data_hex = message.get('data')
            
            if file_data_hex:
                file_path = filedialog.asksaveasfilename(
                    title="Save file as",
                    initialfile=filename
                )
                if file_path:
                    try:
                        file_data = bytes.fromhex(file_data_hex)
                        with open(file_path, 'wb') as f:
                            f.write(file_data)
                        self.add_chat_message("System", f"File '{filename}' received and saved")
                    except Exception as e:
                        self.add_chat_message("System", f"Error saving file: {str(e)}")
    
    def add_chat_message(self, sender, message):
        """Add a message to the chat display"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if sender == "System":
            self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n", "system")
        elif sender.startswith("You →"):
            self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "sent")
        else:
            self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "received")
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
        # Configure tags for colors
        self.chat_display.tag_config("system", foreground="gray")
        self.chat_display.tag_config("sent", foreground="blue")
        self.chat_display.tag_config("received", foreground="green")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = PeerChatGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()

