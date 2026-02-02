import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import sys
import os

# Prompt user for server IP and port
print("\033[36m=== Connect to Server ===\033[0m")
HOST = input("Enter server IP address (e.g., 127.0.0.1 or 192.168.x.x): ").strip()
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
      
      if response == "USERNAME_TAKEN":
        print("\033[31mUsername already taken! Choose another.\033[0m")
        Username()
        return
      elif response == "USERNAME_OK":
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