import socket
import threading
from cryptography.fernet import Fernet
import sys

HOST = "127.0.0.1"
PORT = 8000

def handle_messages():
  while True:
    data = client.recv(1024)
    if not data:
      break
    message = cipher.decrypt(data)
    message = message.decode()
    print(message)


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
key = client.recv(1024)
key = key.decode()
cipher = Fernet(key)

def Username():
  username = input("Enter your username: ")
  if(username != "" and len(username) <= 21):
    client.send(username.encode())
    print("Hello " + username + "!")
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
  message = input()
  if(message != ""):
    encrypted_message = cipher.encrypt(message.encode())
    client.send(encrypted_message)