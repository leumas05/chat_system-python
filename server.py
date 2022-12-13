import threading
import socket
from cryptography.fernet import Fernet
import os

#test

if os.path.exists("secret.key"):
    with open("secret.key", "rb") as key_file:
        key = key_file.read()

users = []
key = Fernet.generate_key()
cipher = Fernet(key)

with open("secret.key", "wb") as key_file:
  key_file.write(key)

HOST = "127.0.0.1"
PORT = 8000

def broadcast(message, sender):
  for user in users:
    if user != sender:
      encrypted_message = cipher.encrypt(message.encode())
      user.send(encrypted_message)


def handle_client(client):
  try:
    username = client.recv(1024)
    username = username.decode()
    users.append(client)
    print("New client user: \"{}\" with the ip: {}".format(username,address))
    while True:
      try:
        data = client.recv(1024)
        if not data:
          break
        message = cipher.decrypt(data)
        message = message.decode()
        print(username + ": " + message)
        broadcast(username + ": " + message, client)
      except Exception as e:
        print("User: \"{}\" left. Ip {}".format(username, address))
        users.remove(client)
        client.close()
        break
  except Exception as e:
    print("Someone without a username left! Ip {}".format(address))


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print("Listening for connections on port {}...".format(PORT))

while True:
  client, address = server.accept()
  client.send(key)
  print("New connection from {}".format(address))
  client_thread = threading.Thread(target=handle_client, args=(client,))
  client_thread.start()