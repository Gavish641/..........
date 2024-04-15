import socket
import threading
import json
import os
#symetric encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
# asymmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_OAEP


from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class MultiThreadedClient(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.chat_messages = []
        self.new_subject = ""
        self.username = ""
        self.messages = []
        self.current_game = []
        self.found_player = False
        self.left_sorting_game = False
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stop_flag = threading.Event() # Event to signal thread termination
        self.client_thread = threading.Thread(target=self.connect)
        
        self.chat_thread = threading.Thread(target=self.receive_messages_chat)
        self.stop_chat_flag = threading.Event()

        self.encryption = Encryption()

    def run(self):
        self.client_thread.start()

    def connect(self):
        self.client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

        # Encryption
        self.server_public_key = RSA.import_key(self.client_socket.recv(1024))
        self.client_socket.sendall(self.encryption.encrypt_symmetric_key(self.server_public_key))

        self.receive_data()
        
    def disconnect(self):
        print("Client disconnected")
        self.stop_flag.set() # Set the stop flag to signal thread termination
        self.client_socket.close()

    def send_message(self, data):
        json_message = json.dumps(data)
        self.client_socket.send(json_message.encode())

    def receive_data(self):
        while not self.stop_flag.is_set(): # Check the stop flag in the loop
            try:
                data = self.client_socket.recv(1024)            
                msg = self.decode_json(data)
                if not msg:
                    break
                if type(msg) is list:
                    self.messages = msg
                    if (msg[0] == "login" or msg[0] == "signup") and msg[1] == "success":
                        self.username = msg[2]
                        
                    elif msg[0] == "game" and msg[1] == "chat":
                        if msg[2] == "joining":
                            self.found_player = True
                        else:
                            self.found_player = False
            except:
                self.client_socket.close()

    def decode_json(self, data):
        if data:
            return json.loads(data)
    
    def connect_to_chat(self):
        self.stop_flag.set()
        self.stop_chat_flag.clear()
        self.chat_thread = threading.Thread(target=self.receive_messages_chat).start()

    def receive_messages_chat(self):
        while not self.stop_chat_flag.is_set():
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                msg = self.decode_json(data)
                if msg[0] and msg[0] == "game" and msg[1] and msg[1] == "chat" and msg[2]:
                    if msg[2] == "new round":
                        self.new_subject = msg[3]
                    elif msg[2] == "kicking client":
                        self.new_subject = msg[2]
                        self.chat_messages.append(msg)
                    else:
                        self.chat_messages.append(msg)
                else:
                    self.chat_messages.append(msg)
            except Exception as e:
                break

    def left_sorting_game(self):
        self.left_sorting_game = True

    def leave_chat(self):
        self.stop_flag.clear()
        self.stop_chat_flag.set()
        self.client_thread = threading.Thread(target=self.receive_data).start()

# class Encryption:
#     def __init__(self, key=None):
#         self.encryption_key = None
#         self.public_key = None
#         self.private_key = None

#     def generate_encryption_key(self, key_length=16):
#         """
#         Generate a strong and unique encryption key.
#         Args:
#             key_length (int): The length of the encryption key in bytes. Default is 32 bytes (256 bits).
#         Returns:
#             bytes: The generated encryption key.
#         """
#         return secrets.token_bytes(key_length)

#     def encrypt_asymmetric(self, plaintext, public_key):
#         # Implement code to encrypt plaintext using asymmetric encryption
#         cipher = PKCS1_OAEP.new(public_key)
#         ciphertext = cipher.encrypt(plaintext)
#         return ciphertext
    
#     def encrypt(self, data, encryption_key):

#         salt = os.urandom(16)
#         nonce = os.urandom(16)
#         # Ensure password is encoded if it's a string
#         if isinstance(data, str):
#             data = data.encode('utf-8')
#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=salt,
#             iterations=100000,
#             backend=default_backend()
#         )
#         key = kdf.derive(encryption_key)  # Replace with your secret key
#         cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
#         encryptor = cipher.encryptor()
#         encrypted_data = encryptor.update(data) + encryptor.finalize()
#         tag = encryptor.tag
#         return [str(encrypted_data), str(salt), str(nonce), str(tag)]
    
#     def decrypt(self, encrypted_password, salt, nonce, tag, encryption_key):
#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=salt,
#             iterations=100000,
#             backend=default_backend()
#         )
#         key = kdf.derive(encryption_key)
#         cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
#         decryptor = cipher.decryptor()
#         decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
#         return decrypted_password


class Encryption:
    def __init__(self):
        # Initialize any necessary variables or objects here
        self.key = RSA.generate(1024)
        self.CHUNK_SIZE = 86
        self.public_key = self.key.publickey()
        self.private_key = self.key
        self.symmetric_key = None
    
    def generate_symetric_key(self):
        # Implement code to generate encryption key
        return Fernet.generate_key()
    
    def import_public_key(self, pem_key):
        return RSA.import_key(pem_key)
    
    def encrypt_data(self, plaintext):
        print(self.symmetric_key, type(self.symmetric_key))
        cipher = Fernet(self.symmetric_key)
        ciphertext = b""
        ciphertext = cipher.encrypt(plaintext)
        
        return ciphertext
    
    def decrypt_data(self, ciphertext):
        cipher = Fernet(self.symmetric_key)
        plaintext = b""
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    
    def encrypt_symmetric_key(self, server_public_key):
        self.symmetric_key = self.generate_symetric_key()
        cipher = PKCS1_OAEP.new(server_public_key)
        chunk_size = 86 
        ciphertext = b"" 
        for i in range(0, len(self.symmetric_key), chunk_size): # Encrypt in chunks
            chunk = self.symmetric_key[i:i + chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            ciphertext += encrypted_chunk
        return ciphertext
    