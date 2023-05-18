import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import hashlib

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client_socket.connect(('localhost', 8000))

key = os.urandom(32)
print(key)
iv = b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'

server_public_key = client_socket.recv(2048)
rsa_key = RSA.import_key(server_public_key)
cipher_rsa = PKCS1_OAEP.new(rsa_key)
encrypted_key = cipher_rsa.encrypt(key)

client_socket.sendall(encrypted_key)
print("To stop the connection write Stop or s.")

while True:
    message = input('Enter a message to send to server: ')
    
    hash_object = hashlib.sha256(message.encode())
    message_hash = hash_object.hexdigest()
    
    padded_message = pad((message_hash + message).encode(), AES.block_size)
    
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(padded_message)
    
    if message == "Stop" or message == 's':
    
        hash_object = hashlib.sha256(message.encode())
        message_hash = hash_object.hexdigest()
        
        padded_message = pad((message_hash + message).encode(), AES.block_size)
        
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(padded_message)
        
        client_socket.sendall(ciphertext)
        break
    else:
        client_socket.sendall(ciphertext)
    
    data = client_socket.recv(1024)
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher_aes.decrypt(data)
    plaintext = unpad(plaintext_padded, AES.block_size).decode()
    
    received_hash = plaintext[:64]
    plaintext = plaintext[64:]
    
    hash_object = hashlib.sha256(plaintext.encode())
    computed_hash = hash_object.hexdigest()
    
    if received_hash != computed_hash:
        print('Message integrity compromised')
        print("Closing connection.")
        break
    
    print('Received message from server:', plaintext)

print("Connection closed.")
client_socket.close()