import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import hashlib
#why
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8000))
server_socket.listen(1)

key_pair = RSA.generate(2048)
public_key = key_pair.publickey().export_key()
print(public_key)

iv = b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'

while True:
    print("\nThe server is listening")
    connection, client_address = server_socket.accept()
    print('Client connected:', client_address)
    
    connection.sendall(public_key)
    
    encrypted_key = connection.recv(2048)
    
    cipher_rsa = PKCS1_OAEP.new(key_pair)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    
    #print('Decrypted AES key:', aes_key.hex())
    #print('Decrypted AES key:', aes_key)
    
    while True:
        data = connection.recv(1024)
        
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
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
        else:
            if plaintext == 's' or plaintext == "Stop":
                print("Client closed connection.")
                break
            print('Received message from client:', plaintext)
            
            message = input('Enter a message to send to client: ')
            
            hash_object = hashlib.sha256(message.encode())
            message_hash = hash_object.hexdigest()
            
            padded_message = pad((message_hash + message).encode(), AES.block_size)
            
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher_aes.encrypt(padded_message)
            
            connection.sendall(ciphertext)
    
    connection.close()