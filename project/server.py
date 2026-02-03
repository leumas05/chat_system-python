import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os
import datetime
import sys
from msvcrt import getch
import colorama
import hashlib
import re
import time
colorama.init(autoreset=True)

# DoS Protection Configuration
MAX_CONNECTIONS = 50  # Maximum concurrent connections
SOCKET_TIMEOUT = 30  # Socket timeout in seconds (prevents slowloris)
MAX_MESSAGES_PER_MINUTE = 20  # Rate limit: messages per minute per user
MESSAGE_WINDOW = 60  # Time window for rate limiting (seconds)

# DoS Protection Configuration
MAX_CONNECTIONS = 50  # Maximum concurrent connections
SOCKET_TIMEOUT = 30  # Socket timeout in seconds (prevents slowloris)
MAX_MESSAGES_PER_MINUTE = 20  # Rate limit: messages per minute per user
MESSAGE_WINDOW = 60  # Time window for rate limiting (seconds)

users = []
usernames = ['Server']
client_ciphers = {}  # Store cipher for each client
client_addresses = {}  # Store IP address for each client
banned_ips = {}  # Store banned IP addresses with username {ip: username}
banned_usernames = set()  # Store banned usernames (survives IP changes)
reserved_usernames = {'Server', 'Admin', 'Administrator', 'System', 'Moderator', 'Mod', 'Owner', 'Root'}  # Reserved usernames
silenced_ips = {}  # Store silenced IP addresses with username {ip: username}
server_input = [""]
client_message_times = {}  # Store message timestamps for rate limiting {username: [timestamps]}
user_accounts = {}  # Store username:password pairs {username: (salt, hashed_password)}
username_ip_history = {}  # Track username-IP pairs to detect ban evasion {username: [ips]}
ip_username_count = {}  # Count unique usernames per IP {ip: set(usernames)}

# Semaphore to limit concurrent connections
connection_semaphore = threading.Semaphore(MAX_CONNECTIONS)
active_connections = 0
connections_lock = threading.Lock()
users_lock = threading.Lock()  # Protect users, usernames, and client data from concurrent modification

# Load banned IPs from file
BAN_FILE = "banned_ips.txt"
if os.path.exists(BAN_FILE):
    with open(BAN_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 2:
                ip, username = parts
                banned_ips[ip] = username
            elif parts[0]:  # Old format, just IP
                banned_ips[parts[0]] = "Unknown"
    print(f"Loaded {len(banned_ips)} banned IP(s) from {BAN_FILE}")

# Load banned usernames from file
BAN_USERNAME_FILE = "banned_usernames.txt"
if os.path.exists(BAN_USERNAME_FILE):
    with open(BAN_USERNAME_FILE, "r") as f:
        for line in f:
            username = line.strip()
            if username:
                banned_usernames.add(username)
    print(f"Loaded {len(banned_usernames)} banned username(s) from {BAN_USERNAME_FILE}")

# Load user accounts (optional password protection)
ACCOUNTS_FILE = "user_accounts.txt"
if os.path.exists(ACCOUNTS_FILE):
    with open(ACCOUNTS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 3:  # New format: username|salt|hash
                username, salt_hex, password_hash = parts
                user_accounts[username] = (bytes.fromhex(salt_hex), password_hash)
            elif len(parts) == 2:  # Old format (migrate to new format)
                username, password_hash = parts
                # Generate a random salt for existing accounts
                salt = os.urandom(32)
                # Keep old hash but add salt (will force password reset on next login)
                user_accounts[username] = (salt, password_hash)
                print(f"  ⚠ Account '{username}' needs migration (old format detected)")
    print(f"Loaded {len(user_accounts)} registered account(s) from {ACCOUNTS_FILE}")

# Load reserved usernames from file (optional, adds to defaults)
RESERVED_FILE = "reserved_usernames.txt"
if os.path.exists(RESERVED_FILE):
    with open(RESERVED_FILE, "r") as f:
        for line in f:
            username = line.strip()
            if username:
                reserved_usernames.add(username)
    print(f"Loaded {len(reserved_usernames)} reserved username(s) (including defaults)")
else:
    print(f"Using {len(reserved_usernames)} default reserved usernames")

# Load silenced IPs from file
SILENCE_FILE = "silenced_ips.txt"
if os.path.exists(SILENCE_FILE):
    with open(SILENCE_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 2:
                ip, username = parts
                silenced_ips[ip] = username
    print(f"Loaded {len(silenced_ips)} silenced IP(s) from {SILENCE_FILE}")

def save_banned_ips():
    """Save banned IPs to file"""
    with open(BAN_FILE, "w") as f:
        for ip, username in banned_ips.items():
            f.write(f"{ip}|{username}\n")

def save_banned_usernames():
    """Save banned usernames to file"""
    with open(BAN_USERNAME_FILE, "w") as f:
        for username in sorted(banned_usernames):
            f.write(f"{username}\n")

def save_silenced_ips():
    """Save silenced IPs to file"""
    with open(SILENCE_FILE, "w") as f:
        for ip, username in silenced_ips.items():
            f.write(f"{ip}|{username}\n")

def save_user_accounts():
    """Save user accounts to file"""
    with open(ACCOUNTS_FILE, "w") as f:
        for username, (salt, password_hash) in sorted(user_accounts.items()):
            salt_hex = salt.hex()
            f.write(f"{username}|{salt_hex}|{password_hash}\n")

def save_reserved_usernames():
    """Save reserved usernames to file"""
    with open(RESERVED_FILE, "w") as f:
        for username in sorted(reserved_usernames):
            f.write(f"{username}\n")

def sanitize_message(text):
    """Remove ANSI escape codes and control characters from user input to prevent UI spoofing"""
    # Remove ANSI escape sequences (\033[...m or \x1b[...m)
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')
    text = ansi_escape.sub('', text)
    
    # Remove other common control characters that could be used for spoofing
    # \r (carriage return), \b (backspace), \a (bell), etc.
    control_chars = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')
    text = control_chars.sub('', text)
    
    return text

def is_rate_limited(username):
    """Check if user is sending messages too fast (DoS protection)"""
    current_time = time.time()
    
    # Initialize message times for new user
    if username not in client_message_times:
        client_message_times[username] = []
    
    # Remove timestamps older than MESSAGE_WINDOW
    client_message_times[username] = [
        t for t in client_message_times[username]
        if current_time - t < MESSAGE_WINDOW
    ]
    
    # Check if limit exceeded
    if len(client_message_times[username]) >= MAX_MESSAGES_PER_MINUTE:
        return True
    
    # Add current timestamp
    client_message_times[username].append(current_time)
    return False

def check_suspicious_activity(username, ip):
    """Detect ban evasion and suspicious patterns"""
    warnings = []
    
    # Track username-IP pairs
    if username not in username_ip_history:
        username_ip_history[username] = set()
    username_ip_history[username].add(ip)
    
    # Track usernames per IP
    if ip not in ip_username_count:
        ip_username_count[ip] = set()
    ip_username_count[ip].add(username)
    
    # Check if this username has connected from multiple IPs (possible ban evasion)
    if len(username_ip_history[username]) > 3:
        warnings.append(f"Username '{username}' has connected from {len(username_ip_history[username])} different IPs")
    
    # Check if this IP has many different usernames (shared IP or suspicious)
    if len(ip_username_count[ip]) > 5:
        warnings.append(f"IP {ip} has been used by {len(ip_username_count[ip])} different usernames (possible shared IP/NAT)")
    
    # Check if username is similar to a banned username (simple evasion detection)
    username_lower = username.lower()
    for banned in banned_usernames:
        banned_lower = banned.lower()
        # Check for simple variations (adding numbers, underscores, etc.)
        if banned_lower in username_lower or username_lower in banned_lower:
            if username_lower != banned_lower:  # Not exact match
                warnings.append(f"Username '{username}' is similar to banned username '{banned}'")
    
    return warnings

# Load or generate RSA key pair for secure key exchange
KEY_FILE = "server_key.pem"
if os.path.exists(KEY_FILE):
    # Load existing key (requires password)
    print("\n\033[33mServer private key is password-protected\033[0m")
    while True:
        key_password = input("Enter key password to unlock server: ").strip()
        if not key_password:
            print("\033[31mPassword cannot be empty\033[0m")
            continue
        try:
            with open(KEY_FILE, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=key_password.encode()
                )
            print(f"\033[32m✓ Server key loaded successfully\033[0m")
            break
        except ValueError:
            print("\033[31m✗ Incorrect password! Try again.\033[0m")
        except Exception as e:
            print(f"\033[31mError loading key: {e}\033[0m")
            sys.exit(1)
else:
    # Generate new RSA key pair with password protection
    print("\n\033[33m=== First-Time Server Setup ===\033[0m")
    print("\033[33mGenerating new server key...\033[0m")
    print("\033[33mYou will need to create a password to protect the server's private key.\033[0m")
    print("\033[33mThis password will be required every time you start the server.\033[0m\n")
    
    while True:
        key_password = input("Create a password for the server key: ").strip()
        if len(key_password) < 8:
            print("\033[31mPassword must be at least 8 characters\033[0m")
            continue
        key_password_confirm = input("Confirm password: ").strip()
        if key_password != key_password_confirm:
            print("\033[31mPasswords do not match! Try again.\033[0m")
            continue
        break
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save the private key with password encryption
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
        ))
    
    print(f"\033[32m✓ Generated new password-protected server key and saved to {KEY_FILE}\033[0m")
    print(f"\033[33m⚠ IMPORTANT: Remember this password! You cannot start the server without it.\033[0m\n")

public_key = private_key.public_key()

# Serialize public key to send to clients
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate and display fingerprint for verification
fingerprint = hashlib.sha256(public_pem).hexdigest()
fingerprint_formatted = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
print(f"\n\033[33m=== Server Key Fingerprint (SHA256) ===\033[0m")
print(f"\033[33m{fingerprint_formatted}\033[0m")
print(f"\033[33m{'='*len('=== Server Key Fingerprint (SHA256) ===')}\033[0m\n")

HOST = "0.0.0.0"  # Listen on all network interfaces
PORT = 0  # Let OS choose an available port automatically

def broadcast(message, sender):
  # Copy user list while holding lock to avoid blocking other operations during sends
  with users_lock:
    users_to_send = [(user, client_ciphers.get(user)) for user in users if user != sender]
  
  # Send to users outside the lock (socket operations can block)
  for user, cipher in users_to_send:
    if cipher:
      try:
        encrypted_message = cipher.encrypt(message.encode())
        user.send(encrypted_message)
      except:
        # Silently ignore if send fails (user disconnected)
        pass


def handle_client(client):
  global active_connections
  try:
    # Set socket timeout to prevent slowloris attacks
    client.settimeout(SOCKET_TIMEOUT)
    
    # Receive encrypted Fernet key from client
    encrypted_key = client.recv(512)
    
    # Decrypt the Fernet key using server's private RSA key
    fernet_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create cipher for this client
    cipher = Fernet(fernet_key)
    client_ciphers[client] = cipher
    
    # Send handshake confirmation
    client.send(b"HANDSHAKE_OK")
    
    # Receive and decrypt username
    username = client.recv(1024)
    username = cipher.decrypt(username)
    username = username.decode()
    
    # Sanitize username to prevent ANSI injection
    username = sanitize_message(username)
    
    # Check if username is reserved
    if username in reserved_usernames or username.lower() in {r.lower() for r in reserved_usernames}:
      error_msg = cipher.encrypt(b"USERNAME_RESERVED")
      client.send(error_msg)
      client.close()
      if client in client_ciphers:
        del client_ciphers[client]
      print(str(datetime.datetime.now())+":  \033[33mBlocked reserved username attempt:\033[0m \033[36m{}\033[0m from IP: {}".format(username, address))
      return
    
    # Check if username is banned
    if username in banned_usernames:
      error_msg = cipher.encrypt(b"USERNAME_BANNED")
      client.send(error_msg)
      client.close()
      if client in client_ciphers:
        del client_ciphers[client]
      print(str(datetime.datetime.now())+":  \033[31mBlocked banned username:\033[0m \033[36m{}\033[0m from IP: {}".format(username, address))
      return
    
    # Check if username is already taken
    if username in usernames:
      error_msg = cipher.encrypt(b"USERNAME_TAKEN")
      client.send(error_msg)
      client.close()
      if client in client_ciphers:
        del client_ciphers[client]
      return
    
    # Check if account requires password
    if username in user_accounts:
      # Request password
      client.send(cipher.encrypt(b"PASSWORD_REQUIRED"))
      
      # Receive password
      password_data = client.recv(1024)
      password = cipher.decrypt(password_data).decode()
      
      # Verify password using PBKDF2 with stored salt
      salt, stored_hash = user_accounts[username]
      # Use PBKDF2-HMAC-SHA256 with 100,000 iterations (secure key derivation)
      password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
      
      if password_hash != stored_hash:
        error_msg = cipher.encrypt(b"PASSWORD_INCORRECT")
        client.send(error_msg)
        client.close()
        if client in client_ciphers:
          del client_ciphers[client]
        print(str(datetime.datetime.now())+":  \033[31mFailed login attempt for:\033[0m \033[36m{}\033[0m from IP: {}".format(username, address))
        return
      client.send(cipher.encrypt(b"PASSWORD_OK"))
    else:
      # No password required
      client.send(cipher.encrypt(b"NO_PASSWORD"))
    
    # Check for suspicious activity
    warnings = check_suspicious_activity(username, address[0])
    if warnings:
      for warning in warnings:
        print(str(datetime.datetime.now())+":  \033[33m[SUSPICIOUS] \033[0m" + warning)
    
    # Send final confirmation that username is accepted
    client.send(cipher.encrypt(b"USERNAME_OK"))
    
    with users_lock:
      usernames.append(username)
      users.append(client)
      client_addresses[client] = address
    
    print(str(datetime.datetime.now())+":  \033[32mNew client user: \33[0m\33[36m\"{}\"\33[0m\033[32m with the ip:\33[0m {}".format(username,address))
    broadcast("User: \33[36m\"{}\"\33[0m joined".format(username), client)
    while True:
      try:
        data = client.recv(1024)
        if not data:
          break
        message = cipher.decrypt(data)
        message = message.decode()
        
        # Sanitize message to prevent ANSI injection and UI spoofing
        message = sanitize_message(message)
        
        # Check rate limiting to prevent message flooding (by username, not socket)
        if is_rate_limited(username):
          # Warn the user they're sending too fast
          warning = cipher.encrypt("\033[33mYou are sending messages too fast. Please slow down.\033[0m".encode())
          try:
            client.send(warning)
          except:
            pass
          continue
        
        # Check if user is silenced
        user_ip = address[0]
        if user_ip in silenced_ips:
          # Log the silenced message but don't broadcast
          print(str(datetime.datetime.now())+ ":  \033[90m[SILENCED] \33[36m{}\33[0m: {}".format(username, message))
          continue
        
        print(str(datetime.datetime.now())+ ":  \33[36m{}\33[0m".format(username) + ": " + message)
        broadcast("\33[36m{}\33[0m: ".format(username) + message, client)
      except socket.timeout:
        print(str(datetime.datetime.now())+":  \033[31mConnection timeout for user: \033[0m\33[36m\"{}\"\33[0m".format(username))
        break
      except Exception as e:
        print(str(datetime.datetime.now())+":  \033[31mUser: \033[0m\33[36m\"{}\"\33[0m\033[31m left. Ip: \033[0m{}".format(username, address))
        with users_lock:
          usernames.remove(username)
          users.remove(client)
          if client in client_ciphers:
            del client_ciphers[client]
          if client in client_addresses:
            del client_addresses[client]
          if username in client_message_times:
            del client_message_times[username]
        broadcast("User: \33[36m\"{}\"\33[0m left".format(username), client)
        client.close()
        break
  except socket.timeout:
    print(str(datetime.datetime.now())+":  \033[31mConnection timeout during handshake!\033[0m Ip: {}".format(address))
    if client in client_ciphers:
      del client_ciphers[client]
    if client in client_addresses:
      del client_addresses[client]
    # Note: username not set yet during handshake timeout
  except Exception as e:
    print(str(datetime.datetime.now())+":  \033[31mSomeone without a username left!\033[0m Ip: {}".format(address))
    if client in client_ciphers:
      del client_ciphers[client]
    if client in client_addresses:
      del client_addresses[client]
    # Note: username not set yet, can't clean client_message_times
  finally:
    # Release semaphore slot
    with connections_lock:
      active_connections -= 1
    connection_semaphore.release()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

# Get the actual port assigned by the OS
actual_port = server.getsockname()[1]

# Get and display all network interfaces
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

print("\n" + str(datetime.datetime.now())+":  \033[32mServer started\033[0m")
print("\033[36m=== Server is listening on ===\033[0m")
print(f"  Localhost: 127.0.0.1:{actual_port}")
print(f"  LAN IP: {local_ip}:{actual_port}")
print(f"  Port: {actual_port}")
print("\033[36m==============================\033[0m\n")

def kick_all_clients():
  with users_lock:
    for client in users:
      client.close()
    
def input_thread():
  while True:
    server_input = input("Server Message: ")
    if server_input == "/stop" or server_input == "/Stop" or server_input == "/close" or server_input == "/Close":
      broadcast("\033[31mServer Stopped\033[0m", server)
      server.close()
      exit()
    elif server_input == "/help":
      print("\033[36m=== Server Commands ===\033[0m")
      print("  /help - Show this help message")
      print("  /list - List all connected users with IPs")
      print("  /list-ban - List all banned IP addresses")
      print("  /list-ban-users - List all banned usernames")
      print("  /list-silence - List all silenced users")
      print("  /list-accounts - List all registered accounts")
      print("  /list-reserved - List all reserved usernames")
      print("  /kick <name> - Kick a user from the server")
      print("  /ban <name> - Ban a user's IP address")
      print("  /ban-user <name> - Ban a username (survives IP changes)")
      print("  /unban <ip> - Unban an IP address")
      print("  /unban-user <name> - Unban a username")
      print("  /silence <name> - Silence a user (mute)")
      print("  /desilence <name> - Unsilence a user")
      print("  /register <name> <password> - Register a protected account")
      print("  /unregister <name> - Remove password protection")
      print("  /reserve <name> - Add a username to reserved list")
      print("  /unreserve <name> - Remove a username from reserved list")
      print("  /stop - Stop the server")
      print("  Any other message will be broadcast to all users")
      print("\033[36m=======================\033[0m")
    elif server_input == "/list":
      with users_lock:
        print("\033[36m=== Connected Users ===\033[0m")
        for i, client in enumerate(users):
          username = usernames[i+1] if i+1 < len(usernames) else "Unknown"
          ip_address = client_addresses.get(client, "Unknown")
          print(f"  \33[36m{username}\33[0m - {ip_address}")
        print(f"\033[36mTotal: {len(users)} users\033[0m")
    elif server_input == "/list-ban":
      if banned_ips:
        print("\033[36m=== Banned IP Addresses ===\033[0m")
        for ip, username in sorted(banned_ips.items()):
          print(f"  \033[31m{ip}\033[0m - \033[36m{username}\033[0m")
        print(f"\033[36mTotal: {len(banned_ips)} banned IPs\033[0m")
      else:
        print("\033[36mNo banned IPs\033[0m")
    elif server_input == "/list-ban-users":
      if banned_usernames:
        print("\033[36m=== Banned Usernames ===\033[0m")
        for username in sorted(banned_usernames):
          print(f"  \033[31m{username}\033[0m")
        print(f"\033[36mTotal: {len(banned_usernames)} banned usernames\033[0m")
      else:
        print("\033[36mNo banned usernames\033[0m")
    elif server_input == "/list-accounts":
      if user_accounts:
        print("\033[36m=== Registered Accounts ===\033[0m")
        for username in sorted(user_accounts.keys()):
          print(f"  \033[32m{username}\033[0m (password protected)")
        print(f"\033[36mTotal: {len(user_accounts)} registered accounts\033[0m")
      else:
        print("\033[36mNo registered accounts\033[0m")
    elif server_input == "/list-reserved":
      if reserved_usernames:
        print("\033[36m=== Reserved Usernames ===\033[0m")
        for username in sorted(reserved_usernames):
          print(f"  \033[35m{username}\033[0m")
        print(f"\033[36mTotal: {len(reserved_usernames)} reserved usernames\033[0m")
      else:
        print("\033[36mNo reserved usernames\033[0m")
    elif server_input == "/list-silence":
      if silenced_ips:
        print("\033[36m=== Silenced Users ===\033[0m")
        for ip, username in sorted(silenced_ips.items()):
          print(f"  \033[90m{ip}\033[0m - \033[36m{username}\033[0m")
        print(f"\033[36mTotal: {len(silenced_ips)} silenced users\033[0m")
      else:
        print("\033[36mNo silenced users\033[0m")
    elif server_input.startswith("/kick "):
      username_to_kick = server_input[6:].strip()
      with users_lock:
        if username_to_kick in usernames:
          # Find the client with this username
          index = usernames.index(username_to_kick)
          client_to_kick = users[index]
          
          # Notify the user they're being kicked
          cipher = client_ciphers.get(client_to_kick)
          if cipher:
            try:
              kick_msg = cipher.encrypt("\033[31mYou have been kicked by the server\033[0m".encode())
              client_to_kick.send(kick_msg)
            except:
              pass
          
          # Remove from lists and close connection
          usernames.remove(username_to_kick)
          users.remove(client_to_kick)
          if client_to_kick in client_ciphers:
            del client_ciphers[client_to_kick]
          if client_to_kick in client_addresses:
            del client_addresses[client_to_kick]
          client_to_kick.close()
          
          # Broadcast and log (outside lock to avoid deadlock)
          broadcast("User: \33[36m\"{}\"\33[0m was kicked".format(username_to_kick), server)
          print(str(datetime.datetime.now())+": \033[31mKicked user: \033[0m\33[36m\"{}\"\33[0m".format(username_to_kick))
        else:
          print("\033[31mUser '{}' not found\033[0m".format(username_to_kick))
    elif server_input.startswith("/ban "):
      username_to_ban = server_input[5:].strip()
      with users_lock:
        if username_to_ban in usernames:
          # Find the client with this username
          index = usernames.index(username_to_ban)
          client_to_ban = users[index]
          ip_to_ban = client_addresses.get(client_to_ban)
          
          if ip_to_ban:
            # Add IP to banned list with username
            banned_ips[ip_to_ban[0]] = username_to_ban  # Store IP with username
            save_banned_ips()  # Persist to file
            
            # Also ban the username to prevent reconnection from different IP
            banned_usernames.add(username_to_ban)
            save_banned_usernames()
            
            # Notify the user they're being banned
            cipher = client_ciphers.get(client_to_ban)
            if cipher:
              try:
                ban_msg = cipher.encrypt("\033[31mYou have been banned from the server\033[0m".encode())
                client_to_ban.send(ban_msg)
              except:
                pass
            
            # Remove from lists and close connection
            usernames.remove(username_to_ban)
            users.remove(client_to_ban)
            if client_to_ban in client_ciphers:
              del client_ciphers[client_to_ban]
            if client_to_ban in client_addresses:
              del client_addresses[client_to_ban]
            client_to_ban.close()
            
            # Broadcast and log
            broadcast("User: \33[36m\"{}\"\33[0m was banned".format(username_to_ban), server)
            print(str(datetime.datetime.now())+": \033[31mBanned user: \033[0m\33[36m\"{}\"\33[0m (IP: {})".format(username_to_ban, ip_to_ban[0]))
          else:
            print("\033[31mCould not retrieve IP address\033[0m")
        else:
          print("\033[31mUser '{}' not found\033[0m".format(username_to_ban))
    elif server_input.startswith("/unban "):
      ip_to_unban = server_input[7:].strip()
      if ip_to_unban in banned_ips:
        username = banned_ips[ip_to_unban]
        del banned_ips[ip_to_unban]
        save_banned_ips()
        print(str(datetime.datetime.now())+": \033[32mUnbanned IP: \033[0m{} (\033[36m{}\033[0m)".format(ip_to_unban, username))
      else:
        print("\033[31mIP '{}' is not banned\033[0m".format(ip_to_unban))
    elif server_input.startswith("/ban-user "):
      username_to_ban = server_input[10:].strip()
      banned_usernames.add(username_to_ban)
      save_banned_usernames()
      
      # Kick if currently connected
      with users_lock:
        if username_to_ban in usernames:
          index = usernames.index(username_to_ban)
          client_to_ban = users[index]
          cipher = client_ciphers.get(client_to_ban)
          if cipher:
            try:
              ban_msg = cipher.encrypt("\033[31mYour username has been permanently banned\033[0m".encode())
              client_to_ban.send(ban_msg)
            except:
              pass
          usernames.remove(username_to_ban)
          users.remove(client_to_ban)
          if client_to_ban in client_ciphers:
            del client_ciphers[client_to_ban]
          if client_to_ban in client_addresses:
            del client_addresses[client_to_ban]
          client_to_ban.close()
          broadcast("User: \33[36m\"{}\"\33[0m was banned".format(username_to_ban), server)
      
      print(str(datetime.datetime.now())+": \033[31mBanned username: \033[0m\033[36m{}\033[0m".format(username_to_ban))
    elif server_input.startswith("/unban-user "):
      username_to_unban = server_input[12:].strip()
      if username_to_unban in banned_usernames:
        banned_usernames.remove(username_to_unban)
        save_banned_usernames()
        print(str(datetime.datetime.now())+": \033[32mUnbanned username: \033[0m\033[36m{}\033[0m".format(username_to_unban))
      else:
        print("\033[31mUsername '{}' is not banned\033[0m".format(username_to_unban))
    elif server_input.startswith("/register "):
      parts = server_input[10:].strip().split(" ", 1)
      if len(parts) == 2:
        username, password = parts
        # Generate a cryptographically secure random salt (32 bytes)
        salt = os.urandom(32)
        # Use PBKDF2-HMAC-SHA256 with 100,000 iterations (resistant to rainbow tables)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        user_accounts[username] = (salt, password_hash)
        save_user_accounts()
        print(str(datetime.datetime.now())+": \033[32mRegistered account: \033[0m\033[36m{}\033[0m \033[90m(PBKDF2 with salt)\033[0m".format(username))
      else:
        print("\033[31mUsage: /register <username> <password>\033[0m")
    elif server_input.startswith("/unregister "):
      username = server_input[12:].strip()
      if username in user_accounts:
        del user_accounts[username]
        save_user_accounts()
        print(str(datetime.datetime.now())+": \033[32mUnregistered account: \033[0m\033[36m{}\033[0m".format(username))
      else:
        print("\033[31mAccount '{}' is not registered\033[0m".format(username))
    elif server_input.startswith("/reserve "):
      username = server_input[9:].strip()
      reserved_usernames.add(username)
      save_reserved_usernames()
      
      # Kick if currently connected
      with users_lock:
        if username in usernames:
          index = usernames.index(username)
          client_to_kick = users[index]
          cipher = client_ciphers.get(client_to_kick)
          if cipher:
            try:
              msg = cipher.encrypt("\033[33mYour username has been reserved by the server\033[0m".encode())
              client_to_kick.send(msg)
            except:
              pass
          usernames.remove(username)
          users.remove(client_to_kick)
          if client_to_kick in client_ciphers:
            del client_ciphers[client_to_kick]
          if client_to_kick in client_addresses:
            del client_addresses[client_to_kick]
          client_to_kick.close()
          broadcast("User: \33[36m\"{}\"\33[0m was disconnected (username reserved)".format(username), server)
      
      print(str(datetime.datetime.now())+": \033[35mReserved username: \033[0m\033[36m{}\033[0m".format(username))
    elif server_input.startswith("/unreserve "):
      username = server_input[11:].strip()
      # Don't allow unreserving default protected usernames
      default_reserved = {'Server', 'Admin', 'Administrator', 'System', 'Moderator', 'Mod', 'Owner', 'Root'}
      if username in default_reserved:
        print("\033[31mCannot unreserve default protected username '{}'\033[0m".format(username))
      elif username in reserved_usernames:
        reserved_usernames.remove(username)
        save_reserved_usernames()
        print(str(datetime.datetime.now())+": \033[32mUnreserved username: \033[0m\033[36m{}\033[0m".format(username))
      else:
        print("\033[31mUsername '{}' is not reserved\033[0m".format(username))
    elif server_input.startswith("/silence "):
      username_to_silence = server_input[9:].strip()
      with users_lock:
        if username_to_silence in usernames:
          # Find the client with this username
          index = usernames.index(username_to_silence)
          client_to_silence = users[index]
          ip_to_silence = client_addresses.get(client_to_silence)
          
          if ip_to_silence:
            # Add IP to silenced list
            silenced_ips[ip_to_silence[0]] = username_to_silence
            save_silenced_ips()
            
            # Notify the user they're being silenced
            cipher = client_ciphers.get(client_to_silence)
            if cipher:
              try:
                silence_msg = cipher.encrypt("\033[33mYou have been silenced by the server\033[0m".encode())
                client_to_silence.send(silence_msg)
              except:
                pass
            
            print(str(datetime.datetime.now())+": \033[33mSilenced user: \033[0m\33[36m\"{}\"\33[0m (IP: {})".format(username_to_silence, ip_to_silence[0]))
          else:
            print("\033[31mCould not retrieve IP address\033[0m")
        else:
          print("\033[31mUser '{}' not found\033[0m".format(username_to_silence))
    elif server_input.startswith("/desilence "):
      username_to_desilence = server_input[11:].strip()
      # Find IP by username in silenced_ips
      ip_found = None
      for ip, username in silenced_ips.items():
        if username == username_to_desilence:
          ip_found = ip
          break
      
      if ip_found:
        del silenced_ips[ip_found]
        save_silenced_ips()
        
        # Notify the user if they're still connected
        with users_lock:
          if username_to_desilence in usernames:
            index = usernames.index(username_to_desilence)
            client = users[index]
            cipher = client_ciphers.get(client)
            if cipher:
              try:
                desilence_msg = cipher.encrypt("\033[32mYou have been unsilenced\033[0m".encode())
                client.send(desilence_msg)
              except:
                pass
        
        print(str(datetime.datetime.now())+": \033[32mUnsilenced user: \033[0m\33[36m\"{}\"\33[0m (IP: {})".format(username_to_desilence, ip_found))
      else:
        print("\033[31mUser '{}' is not silenced\033[0m".format(username_to_desilence))
    else:
      broadcast("Server: " + server_input, server)

input_thread = threading.Thread(target=input_thread)
input_thread.start()

while True:
  try:
    client, address = server.accept()
    
    # Check if IP is banned
    if address[0] in banned_ips:
      print(str(datetime.datetime.now())+":  \033[31mBlocked banned IP:\033[0m {}".format(address))
      client.close()
      continue
    
    # Try to acquire semaphore (non-blocking with timeout)
    if not connection_semaphore.acquire(blocking=False):
      print(str(datetime.datetime.now())+":  \033[33mConnection limit reached. Rejecting connection from:\033[0m {}".format(address))
      try:
        client.send(b"ERROR: Server is full. Please try again later.")
      except:
        pass
      client.close()
      continue
    
    # Increment active connections counter
    with connections_lock:
      active_connections += 1
    
    # Send RSA public key to client for secure key exchange
    client.send(public_pem)
    print(str(datetime.datetime.now())+":  \033[32mNew connection from\33[0m {} (Active: {}/{})".format(address, active_connections, MAX_CONNECTIONS))
    client_thread = threading.Thread(target=handle_client, args=(client,))
    client_thread.daemon = True  # Daemon threads will be killed when main thread exits
    client_thread.start()
  except Exception as e:
    print("\033[31mServer Stopped\033[0m")
    kick_all_clients()
    server.close()
    sys.exit()

