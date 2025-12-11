# Quick Start Guide

## 🚀 Fastest Way to Get Started

### Option 1: Using Docker (Recommended)

```bash
# Start everything with one command
docker-compose up -d

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

### Option 2: Local Installation

#### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 2: Start Redis
```bash
# Windows (using Docker)
docker run -d -p 6379:6379 redis:7-alpine

# Linux/Mac
redis-server
```

#### Step 4: Start Peer GUI
```bash
# Open in separate terminal/window
python peer_gui.py
```

## 📝 Basic Usage

1. **Login**: Enter username and port (e.g., "alice", "8888")
2. **Refresh Peers**: Click "Refresh" to see online peers
3. **Connect**: Select a peer and click "Connect to Selected"
4. **Chat**: Select connected peer, type message, press Enter
5. **Send File**: Click "Send File" and select file

## 🧪 Testing

### Test STUN Server
```bash
python test_stun_server.py
```

### Test with CLI (No GUI)
```bash
# Terminal 1
python peer_cli.py peer1 8888

# Terminal 2
python peer_cli.py peer2 8889
```

## 🔍 Verify Installation

1. Check Redis: `redis-cli ping` (should return "PONG")
2. Check STUN Server: Open `http://localhost:5000/health` in browser
3. Check Peers: Run `python test_stun_server.py`

## ⚠️ Common Issues

- **Port in use**: Change TCP port in peer configuration
- **Redis connection error**: Ensure Redis is running
- **GUI not starting**: Install tkinter: `sudo apt-get install python3-tk` (Linux)

## 📚 Full Documentation

See [README.md](README.md) for complete documentation.

