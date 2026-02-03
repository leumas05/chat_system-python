# Secure Chat System

A fully encrypted, feature-rich chat server and client system built in Python with enterprise-grade security features.

## Features

### 🔐 Security
- **End-to-End Encryption**: RSA (2048-bit) + Fernet (AES-128) hybrid encryption
- **Server Authentication**: Trust-On-First-Use (TOFU) with SHA256 fingerprint verification
- **MITM Protection**: Persistent server keys with fingerprint validation
- **Input Sanitization**: ANSI escape code filtering to prevent UI spoofing
- **DoS Protection**: Connection limits, rate limiting, and socket timeouts
- **Password Protection**: Optional SHA256-hashed password authentication for accounts

### 👥 User Management
- **Username Banning**: Ban by username (survives IP changes) or IP address
- **Reserved Usernames**: Protect admin/system usernames from being taken
- **Password-Protected Accounts**: Register accounts with password authentication
- **User Silencing**: Mute users without disconnecting them
- **Kick/Ban System**: Temporary removal or permanent bans

### 🛡️ Anti-Abuse
- **Rate Limiting**: Max 20 messages per minute per user (configurable)
- **Connection Limits**: Max 50 concurrent connections (configurable)
- **Suspicious Activity Detection**: Tracks username-IP patterns for ban evasion
- **Socket Timeouts**: 30-second timeout prevents slowloris attacks
- **IP & Username Tracking**: Detect ban evasion and shared IPs

### 💬 Chat Features
- **Broadcast Messaging**: Server-wide announcements
- **User Join/Leave Notifications**: Track who enters and exits
- **Colored Terminal Output**: User-friendly ANSI color-coded messages
- **Server Commands**: Comprehensive admin control system

## Requirements

```
Python 3.7+
cryptography
colorama
```

## Installation

1. **Clone or download the repository**

2. **Install dependencies:**
   ```bash
   pip install cryptography colorama
   ```

3. **File structure:**
   ```
   chat/
   ├── project/
   │   ├── server.py
   │   └── client/
   │       └── client.py
   └── README.md
   ```

## Usage

### Starting the Server

```bash
cd project
python server.py
```

The server will:
- Generate or load RSA keys from `server_key.pem`
- Display the server fingerprint (verify this on first client connection)
- Auto-select an available port
- Show connection details (localhost + LAN IP)

**Example output:**
```
Loaded existing server key from server_key.pem

=== Server Key Fingerprint (SHA256) ===
a1:b2:c3:d4:e5:f6:... (verify this on clients!)
========================================

Server started
=== Server is listening on ===
  Localhost: 127.0.0.1:52847
  LAN IP: 192.168.1.100:52847
  Port: 52847
==============================
```

### Connecting with a Client

```bash
cd project/client
python client.py
```

1. **Enter server address:** 
   - Format: `192.168.1.100:52847` (IP:port in one input)
   - Or enter IP, then port separately

2. **Verify server fingerprint** (first connection):
   - Compare displayed fingerprint with server's fingerprint
   - Type `yes` to trust and save

3. **Choose username:**
   - Max 20 characters
   - Cannot use reserved names (Admin, Server, etc.)
   - Password required if account is registered

4. **Start chatting!**

## Server Commands

Access these commands from the server console:

| Command | Description |
|---------|-------------|
| `/help` | Display all commands |
| `/list` | Show all connected users with IPs |
| `/list-ban` | List all banned IP addresses |
| `/list-ban-users` | List all banned usernames |
| `/list-reserved` | List all reserved usernames |
| `/list-accounts` | List password-protected accounts |
| `/list-silence` | List all silenced users |
| `/kick <name>` | Disconnect a user (temporary) |
| `/ban <name>` | Ban user's IP + username permanently |
| `/ban-user <name>` | Ban username only (survives IP changes) |
| `/unban <ip>` | Remove IP ban |
| `/unban-user <name>` | Remove username ban |
| `/silence <name>` | Mute a user (messages hidden) |
| `/desilence <name>` | Unmute a user |
| `/register <name> <pass>` | Create password-protected account |
| `/unregister <name>` | Remove password protection |
| `/reserve <name>` | Reserve a username (cannot be taken) |
| `/unreserve <name>` | Unreserve a username |
| `/stop` | Shut down the server |
| Any other text | Broadcast message to all users |

## Client Commands

| Command | Description |
|---------|-------------|
| `/quit` or `/exit` | Disconnect from server |
| `/clear` or `/clean` | Clear terminal screen |

## Configuration

Edit these constants in `server.py`:

```python
MAX_CONNECTIONS = 50           # Maximum concurrent users
SOCKET_TIMEOUT = 30            # Timeout in seconds
MAX_MESSAGES_PER_MINUTE = 20   # Rate limit per user
MESSAGE_WINDOW = 60            # Time window for rate limiting
```

### Default Reserved Usernames
```python
'Server', 'Admin', 'Administrator', 'System', 
'Moderator', 'Mod', 'Owner', 'Root'
```

## Persistent Data Files

The server creates these files to maintain state:

| File | Purpose |
|------|---------|
| `server_key.pem` | RSA private key (server identity) |
| `banned_ips.txt` | Banned IP addresses with usernames |
| `banned_usernames.txt` | Banned usernames (survives IP changes) |
| `user_accounts.txt` | Password-protected accounts (SHA256 hashes) |
| `reserved_usernames.txt` | Additional reserved usernames |
| `silenced_ips.txt` | Muted users by IP |

**Client files:**
| File | Purpose |
|------|---------|
| `known_server_<IP>_<PORT>.txt` | Saved server fingerprints for TOFU |

## Security Architecture

### Encryption Flow

1. **Key Exchange (RSA)**
   - Server sends public key to client
   - Client verifies fingerprint (TOFU)
   - Client generates Fernet key
   - Client encrypts Fernet key with server's public key
   - Server decrypts with private key

2. **Session Encryption (Fernet/AES)**
   - All messages encrypted with unique per-session Fernet key
   - Forward secrecy: new key per connection

### Authentication Flow

```
Client connects
  ↓
Verify server fingerprint (TOFU)
  ↓
Send username (encrypted)
  ↓
Server checks: Reserved? → Reject
               Banned?   → Reject
               Taken?    → Reject
               Password? → Request password
  ↓
Username accepted → Join chat
```

## Troubleshooting

**"Couldn't connect to server"**
- Check IP address and port
- Ensure server is running
- Verify firewall settings

**"WARNING: SERVER IDENTITY HAS CHANGED!"**
- Server's key has changed (regenerated or different server)
- Could indicate MITM attack
- Only accept if you know the server was reset

**"Username is reserved"**
- Choose a different username
- Reserved names protect admin accounts

**"You are sending messages too fast"**
- Rate limit triggered (20 msg/min default)
- Wait a moment before sending more

## License

See LICENSE file for details.

## Contributing

This is a learning/demonstration project showcasing secure chat architecture. Contributions welcome!

## Security Notes

⚠️ **For Educational/Internal Use**: While this system implements many security best practices, it's designed for learning and internal networks, not production internet-facing deployments.

**Implemented protections:**
- ✅ Encryption in transit
- ✅ Server authentication (TOFU)
- ✅ DoS mitigation
- ✅ Input sanitization
- ✅ Rate limiting
- ✅ Access control

**Not implemented:**
- ❌ TLS/SSL certificate chain validation
- ❌ Perfect Forward Secrecy (PFS) key rotation
- ❌ Message integrity verification (HMAC)
- ❌ Replay attack prevention
- ❌ Audit logging
- ❌ Database backend

For production use, consider established solutions like Matrix, XMPP, or Rocket.Chat.
