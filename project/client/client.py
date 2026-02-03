import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import sys
import os
import colorama
import hashlib
colorama.init(autoreset=True)

# Prompt user for server IP and port
print("\033[36m=== Connect to Server ===\033[0m")
HOST = input("Enter server IP address (e.g., 127.0.0.1 or 192.168.x.x:63592): ").strip()

# Check if port is included in the IP address
if ':' in HOST:
  try:
    ip_part, port_part = HOST.rsplit(':', 1)
    PORT = int(port_part)
    HOST = ip_part
    if not (1 <= PORT <= 65535):
      print("\033[31mPort must be between 1 and 65535\033[0m")
      PORT = None
  except ValueError:
    print("\033[31mInvalid port in address, please enter port separately\033[0m")
    PORT = None
else:
  PORT = None

# If port wasn't provided or was invalid, ask for it
if PORT is None:
  while True:
    try:
      PORT = int(input("Enter server port: ").strip())
      if 1 <= PORT <= 65535:
        break
      else:
        print("\033[31mPort must be between 1 and 65535\033[0m")
    except ValueError:
      print("\033[31mPlease enter a valid number\033[0m")

print(f"\033[36mConnecting to {HOST}:{PORT}...\033[0m\n")

def handle_messages():
  while True:
    try:
      data = client.recv(1024)
      if not data:
        break
      message = cipher.decrypt(data)
      message = message.decode()
      print(message)
    except Exception as e:
      print("\033[31mLost connection to server\033[0m")
      sys.exit()
      
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  client.connect((HOST, PORT))
  
  # Receive server's RSA public key
  public_pem = client.recv(2048)
  server_public_key = serialization.load_pem_public_key(public_pem)
  
  # Generate fingerprint of the server's public key
  fingerprint = hashlib.sha256(public_pem).hexdigest()
  fingerprint_formatted = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
  
  # Check if we have a known fingerprint for this server
  FINGERPRINT_FILE = f"known_server_{HOST}_{PORT}.txt"
  
  if os.path.exists(FINGERPRINT_FILE):
    # Verify against known fingerprint
    with open(FINGERPRINT_FILE, "r") as f:
      known_fingerprint = f.read().strip()
    
    if fingerprint != known_fingerprint:
      print("\033[31m" + "="*70 + "\033[0m")
      print("\033[31mWARNING: SERVER IDENTITY HAS CHANGED!\033[0m")
      print("\033[31m" + "="*70 + "\033[0m")
      print("\033[33mThe server's fingerprint does not match the known fingerprint.\033[0m")
      print("\033[33mThis could indicate a Man-in-the-Middle attack!\033[0m")
      print(f"\n\033[33mExpected: {':'.join([known_fingerprint[i:i+2] for i in range(0, len(known_fingerprint), 2)])}\033[0m")
      print(f"\033[31mReceived: {fingerprint_formatted}\033[0m")
      print("\n\033[33mDo you want to continue anyway? (yes/no): \033[0m", end="")
      response = input().strip().lower()
      if response != "yes":
        print("\033[31mConnection aborted for security reasons\033[0m")
        client.close()
        sys.exit(1)
      else:
        # Update the fingerprint
        with open(FINGERPRINT_FILE, "w") as f:
          f.write(fingerprint)
        print("\033[33mFingerprint updated\033[0m")
    else:
      print("\033[32m✓ Server identity verified\033[0m")
  else:
    # First time connecting to this server - Trust On First Use (TOFU)
    print("\033[33m" + "="*70 + "\033[0m")
    print("\033[33mFIRST TIME CONNECTING TO THIS SERVER\033[0m")
    print("\033[33m" + "="*70 + "\033[0m")
    print("\033[33mServer fingerprint (SHA256):\033[0m")
    print(f"\033[33m{fingerprint_formatted}\033[0m")
    print("\n\033[33mVerify this fingerprint matches what the server displays.\033[0m")
    print("\033[33mDo you want to trust this server? (yes/no): \033[0m", end="")
    response = input().strip().lower()
    if response != "yes":
      print("\033[31mConnection aborted\033[0m")
      client.close()
      sys.exit(1)
    else:
      # Save the fingerprint for future connections
      with open(FINGERPRINT_FILE, "w") as f:
        f.write(fingerprint)
      print("\033[32m✓ Server fingerprint saved\033[0m")
  
  # Generate our own Fernet key for symmetric encryption
  fernet_key = Fernet.generate_key()
  cipher = Fernet(fernet_key)
  
  # Encrypt the Fernet key with server's public RSA key
  encrypted_key = server_public_key.encrypt(
      fernet_key,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  
  # Send encrypted Fernet key to server
  client.send(encrypted_key)
  
  # Wait for handshake confirmation
  confirmation = client.recv(1024)
  if confirmation != b"HANDSHAKE_OK":
    print("\033[31mHandshake failed\033[0m")
    sys.exit()
  
  print("\033[32m✓ Secure connection established\033[0m")
  
except Exception as e:
  print("\033[31mCouldn't connect to server\033[0m")
  print(f"Error: {e}")
  sys.exit()


def Username():
  username = input("Enter your username: ")
  if(username != "" and len(username) <= 20):
    encrypted_username = cipher.encrypt(username.encode())
    try:
      client.send(encrypted_username)
      
      # Wait for server response
      response = client.recv(1024)
      response = cipher.decrypt(response).decode()
      
      if response == "USERNAME_BANNED":
        print("\033[31mThis username is banned from the server!\033[0m")
        Username()
        return
      elif response == "USERNAME_RESERVED":
        print("\033[33mThis username is reserved and cannot be used.\033[0m")
        Username()
        return
      elif response == "USERNAME_TAKEN":
        print("\033[31mUsername already taken! Choose another.\033[0m")
        Username()
        return
      elif response == "PASSWORD_REQUIRED":
        # Account requires password
        password = input("\033[33mThis account is password protected. Enter password: \033[0m")
        encrypted_password = cipher.encrypt(password.encode())
        client.send(encrypted_password)
        
        # Wait for password verification
        pass_response = client.recv(1024)
        pass_response = cipher.decrypt(pass_response).decode()
        
        if pass_response == "PASSWORD_INCORRECT":
          print("\033[31mIncorrect password!\033[0m")
          Username()
          return
        elif pass_response == "PASSWORD_OK":
          # Wait for final confirmation
          final_response = client.recv(1024)
          final_response = cipher.decrypt(final_response).decode()
          if final_response == "USERNAME_OK":
            print("Hello \033[33m{}\033[0m! (Authenticated)".format(username))
      elif response == "NO_PASSWORD":
        # No password required, wait for final confirmation
        final_response = client.recv(1024)
        final_response = cipher.decrypt(final_response).decode()
        if final_response == "USERNAME_OK":
          print("Hello \033[33m{}\033[0m!".format(username))
      elif response == "USERNAME_OK":
        # Old server version without password support
        print("Hello \033[33m{}\033[0m!".format(username))
      
    except Exception as e:
      print("\033[31mFailed to connect to server\033[0m")
      sys.exit()
  elif(len(username) > 21):
    print("Maximum characters in a username is 21")
    Username()
  elif(username == ""):
    print("You have to write something!")
    Username()
  else:
    Username()

Username()

message_thread = threading.Thread(target=handle_messages)
message_thread.start()

while True:
  try:
    message = input()
    if message == "/quit" or message == "/exit":
      print("\033[33mDisconnecting from server...\033[0m")
      client.close()
      sys.exit(0)
    elif message == "/clean" or message == "/clear":
      # Clear the terminal screen
      os.system('cls' if os.name == 'nt' else 'clear')
    elif(message != ""):
      encrypted_message = cipher.encrypt(message.encode())
      client.send(encrypted_message)
  except Exception as e:
    print("\033[31mError\033[0m")
    exit()