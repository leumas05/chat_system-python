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
colorama.init(autoreset=True)

users = []
usernames = ['Server']
client_ciphers = {}  # Store cipher for each client
client_addresses = {}  # Store IP address for each client
banned_ips = {}  # Store banned IP addresses with username {ip: username}
silenced_ips = {}  # Store silenced IP addresses with username {ip: username}
server_input = [""]

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

def save_silenced_ips():
    """Save silenced IPs to file"""
    with open(SILENCE_FILE, "w") as f:
        for ip, username in silenced_ips.items():
            f.write(f"{ip}|{username}\n")

# Generate RSA key pair for secure key exchange
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Serialize public key to send to clients
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

HOST = "0.0.0.0"  # Listen on all network interfaces
PORT = 0  # Let OS choose an available port automatically

def broadcast(message, sender):
  for user in users:
    if user != sender:
      cipher = client_ciphers.get(user)
      if cipher:
        encrypted_message = cipher.encrypt(message.encode())
        user.send(encrypted_message)


def handle_client(client):
  try:
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
    
    # Check if username is already taken
    if username in usernames:
      error_msg = cipher.encrypt(b"USERNAME_TAKEN")
      client.send(error_msg)
      client.close()
      if client in client_ciphers:
        del client_ciphers[client]
      return
    
    # Send confirmation that username is accepted
    client.send(cipher.encrypt(b"USERNAME_OK"))
    
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
        
        # Check if user is silenced
        user_ip = address[0]
        if user_ip in silenced_ips:
          # Log the silenced message but don't broadcast
          print(str(datetime.datetime.now())+ ":  \033[90m[SILENCED] \33[36m{}\33[0m: {}".format(username, message))
          continue
        
        print(str(datetime.datetime.now())+ ":  \33[36m{}\33[0m".format(username) + ": " + message)
        broadcast("\33[36m{}\33[0m: ".format(username) + message, client)
      except Exception as e:
        print(str(datetime.datetime.now())+":  \033[31mUser: \033[0m\33[36m\"{}\"\33[0m\033[31m left. Ip: \033[0m{}".format(username, address))
        usernames.remove(username)
        broadcast("User: \33[36m\"{}\"\33[0m left".format(username), client)
        users.remove(client)
        if client in client_ciphers:
          del client_ciphers[client]
        if client in client_addresses:
          del client_addresses[client]
        client.close()
        break
  except Exception as e:
    print(str(datetime.datetime.now())+":  \033[31mSomeone without a username left!\033[0m Ip: {}".format(address))
    if client in client_ciphers:
      del client_ciphers[client]
    if client in client_addresses:
      del client_addresses[client]

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
      print("  /list-silence - List all silenced users")
      print("  /kick <name> - Kick a user from the server")
      print("  /ban <name> - Ban a user's IP address")
      print("  /unban <ip> - Unban an IP address")
      print("  /silence <name> - Silence a user (mute)")
      print("  /desilence <name> - Unsilence a user")
      print("  /stop - Stop the server")
      print("  Any other message will be broadcast to all users")
      print("\033[36m=======================\033[0m")
    elif server_input == "/list":
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
        
        # Broadcast and log
        broadcast("User: \33[36m\"{}\"\33[0m was kicked".format(username_to_kick), server)
        print(str(datetime.datetime.now())+": \033[31mKicked user: \033[0m\33[36m\"{}\"\33[0m".format(username_to_kick))
      else:
        print("\033[31mUser '{}' not found\033[0m".format(username_to_kick))
    elif server_input.startswith("/ban "):
      username_to_ban = server_input[5:].strip()
      if username_to_ban in usernames:
        # Find the client with this username
        index = usernames.index(username_to_ban)
        client_to_ban = users[index]
        ip_to_ban = client_addresses.get(client_to_ban)
        
        if ip_to_ban:
          # Add IP to banned list with username
          banned_ips[ip_to_ban[0]] = username_to_ban  # Store IP with username
          save_banned_ips()  # Persist to file
          
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
    elif server_input.startswith("/silence "):
      username_to_silence = server_input[9:].strip()
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
    
    # Send RSA public key to client for secure key exchange
    client.send(public_pem)
    print(str(datetime.datetime.now())+":  \033[32mNew connection from\33[0m {}".format(address))
    client_thread = threading.Thread(target=handle_client, args=(client,))
    client_thread.start()
  except Exception as e:
    print("\033[31mServer Stopped\033[0m")
    kick_all_clients()
    server.close()
    sys.exit()

