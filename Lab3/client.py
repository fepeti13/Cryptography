import socket
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Client:
    def __init__(self, client_id, client_port, keyserver_host="localhost", keyserver_port=8080):
        self.client_id = client_id
        self.client_port = client_port
        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port
        
        
        print(f"[CLIENT {self.client_id}]: Generating RSA-2048 keypair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[CLIENT {self.client_id}]: RSA keypair generated")
        
        
        self.supported_ciphers = ["AES-256-CBC", "AES-128-CBC"]
        self.symmetric_key = None
        self.chosen_cipher = None
        
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("localhost", self.client_port))
        self.server_socket.listen(1)
        
        
        self.server_thread = threading.Thread(target=self._listen_for_connections, daemon=True)
        self.server_thread.start()
        
    def _serialize_public_key(self):
        """Serialize public key to PEM format"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def _deserialize_public_key(self, pem_string):
        """Deserialize public key from PEM format"""
        return serialization.load_pem_public_key(
            pem_string.encode('utf-8'),
            backend=default_backend()
        )
    
    def register_with_keyserver(self):
        """Register public key with KeyServer"""
        print(f"[CLIENT {self.client_id}]: Registering with KeyServer...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.keyserver_host, self.keyserver_port))
        
        request = {
            "function": "register_public_key",
            "params": {
                "id_client": self.client_id,
                "public_key": self._serialize_public_key()
            }
        }
        
        s.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(s.recv(4096).decode('utf-8'))
        s.close()
        
        print(f"[CLIENT {self.client_id}]: Registration response: {response['message']}")
        return response['status'] == 'success'
    
    def get_peer_public_key(self, peer_id):
        """Get peer's public key from KeyServer"""
        print(f"[CLIENT {self.client_id}]: Requesting public key for client {peer_id}...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.keyserver_host, self.keyserver_port))
        
        request = {
            "function": "get_public_key",
            "params": {
                "id_client": peer_id
            }
        }
        
        s.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(s.recv(4096).decode('utf-8'))
        s.close()
        
        if response['status'] == 'success':
            print(f"[CLIENT {self.client_id}]: Received public key for client {peer_id}")
            return self._deserialize_public_key(response['key'])
        else:
            print(f"[CLIENT {self.client_id}]: Failed to get public key: {response['message']}")
            return None
    
    def _rsa_encrypt(self, message, public_key):
        """Encrypt message with RSA public key"""
        return public_key.encrypt(
            message.encode('utf-8') if isinstance(message, str) else message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def _rsa_decrypt(self, ciphertext):
        """Decrypt message with RSA private key"""
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def _aes_encrypt(self, message):
        """Encrypt message with AES"""
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        return cipher.iv + ct_bytes
    
    def _aes_decrypt(self, ciphertext):
        """Decrypt message with AES"""
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    
    def initiate_communication(self, peer_id, peer_port):
        """Initiate communication as Client1"""
        print(f"\n[CLIENT {self.client_id}]: Initiating communication with client {peer_id}")
        
        
        peer_public_key = self.get_peer_public_key(peer_id)
        if not peer_public_key:
            print(f"[CLIENT {self.client_id}]: Cannot get peer public key, aborting")
            return
        
        
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect(("localhost", peer_port))
        
        
        print(f"[CLIENT {self.client_id}]: Sending HELLO with cipher list")
        hello_msg = json.dumps({
            "type": "HELLO",
            "client_id": self.client_id,
            "ciphers": self.supported_ciphers
        })
        encrypted_hello = self._rsa_encrypt(hello_msg, peer_public_key)
        peer_socket.sendall(len(encrypted_hello).to_bytes(4, 'big') + encrypted_hello)
        
        
        msg_len = int.from_bytes(peer_socket.recv(4), 'big')
        encrypted_ack = peer_socket.recv(msg_len)
        ack_msg = json.loads(self._rsa_decrypt(encrypted_ack).decode('utf-8'))
        print(f"[CLIENT {self.client_id}]: Received ACK, chosen cipher: {ack_msg['chosen_cipher']}")
        self.chosen_cipher = ack_msg['chosen_cipher']
        
        
        print(f"[CLIENT {self.client_id}]: Generating secret key1")
        key1 = get_random_bytes(16)
        print(f"[CLIENT {self.client_id}]: Sending half secret (key1)")
        encrypted_key1 = self._rsa_encrypt(key1, peer_public_key)
        peer_socket.sendall(len(encrypted_key1).to_bytes(4, 'big') + encrypted_key1)
        
        
        msg_len = int.from_bytes(peer_socket.recv(4), 'big')
        encrypted_key2 = peer_socket.recv(msg_len)
        key2 = self._rsa_decrypt(encrypted_key2)
        print(f"[CLIENT {self.client_id}]: Received half secret (key2)")
        
        
        self.symmetric_key = bytes(a ^ b for a, b in zip(key1, key2))
        print(f"[CLIENT {self.client_id}]: Generated common symmetric key")
        print(f"[CLIENT {self.client_id}]: Initialized block cipher: {self.chosen_cipher}")
        
        
        self._exchange_messages(peer_socket, is_initiator=True)
        
        peer_socket.close()
        print(f"[CLIENT {self.client_id}]: Communication ended")
    
    def _listen_for_connections(self):
        """Listen for incoming connections"""
        print(f"[CLIENT {self.client_id}]: Listening on port {self.client_port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            print(f"[CLIENT {self.client_id}]: Accepted connection from {address}")
            threading.Thread(target=self._handle_peer, args=(client_socket,), daemon=True).start()
    
    def _handle_peer(self, peer_socket):
        """Handle incoming connection as Client2"""
        try:
            
            msg_len = int.from_bytes(peer_socket.recv(4), 'big')
            encrypted_hello = peer_socket.recv(msg_len)
            hello_msg = json.loads(self._rsa_decrypt(encrypted_hello).decode('utf-8'))
            peer_id = hello_msg['client_id']
            peer_ciphers = hello_msg['ciphers']
            print(f"[CLIENT {self.client_id}]: Received HELLO from client {peer_id}")
            print(f"[CLIENT {self.client_id}]: Peer supports: {peer_ciphers}")
            
            
            common_cipher = None
            for cipher in self.supported_ciphers:
                if cipher in peer_ciphers:
                    common_cipher = cipher
                    break
            
            if not common_cipher:
                print(f"[CLIENT {self.client_id}]: No common cipher found!")
                peer_socket.close()
                return
            
            self.chosen_cipher = common_cipher
            print(f"[CLIENT {self.client_id}]: Chosen cipher: {common_cipher}")
            
            
            peer_public_key = self.get_peer_public_key(peer_id)
            
            
            print(f"[CLIENT {self.client_id}]: Sending ACK")
            ack_msg = json.dumps({
                "type": "ACK",
                "client_id": self.client_id,
                "chosen_cipher": common_cipher
            })
            encrypted_ack = self._rsa_encrypt(ack_msg, peer_public_key)
            peer_socket.sendall(len(encrypted_ack).to_bytes(4, 'big') + encrypted_ack)
            
            
            msg_len = int.from_bytes(peer_socket.recv(4), 'big')
            encrypted_key1 = peer_socket.recv(msg_len)
            key1 = self._rsa_decrypt(encrypted_key1)
            print(f"[CLIENT {self.client_id}]: Received half secret (key1)")
            
            
            print(f"[CLIENT {self.client_id}]: Generating secret key2")
            key2 = get_random_bytes(16)
            print(f"[CLIENT {self.client_id}]: Sending half secret (key2)")
            encrypted_key2 = self._rsa_encrypt(key2, peer_public_key)
            peer_socket.sendall(len(encrypted_key2).to_bytes(4, 'big') + encrypted_key2)
            
            
            self.symmetric_key = bytes(a ^ b for a, b in zip(key1, key2))
            print(f"[CLIENT {self.client_id}]: Generated common symmetric key")
            print(f"[CLIENT {self.client_id}]: Initialized block cipher: {self.chosen_cipher}")
            
            
            self._exchange_messages(peer_socket, is_initiator=False)
            
        except Exception as e:
            print(f"[CLIENT {self.client_id}]: Error handling peer: {e}")
        finally:
            peer_socket.close()
    
    def _exchange_messages(self, peer_socket, is_initiator):
        """Exchange encrypted messages with peer"""
        print(f"\n[CLIENT {self.client_id}]: Starting encrypted message exchange")
        
        
        messages_to_send = [
            "This is the first encrypted message. " * 10,  
            "This is the second encrypted message with different content to ensure we meet the requirement. " * 5  
        ]
        
        for i, msg in enumerate(messages_to_send):
            if is_initiator:
                
                print(f"[CLIENT {self.client_id}]: Sending encrypted message {i+1} ({len(msg)} chars)")
                encrypted_msg = self._aes_encrypt(msg)
                peer_socket.sendall(len(encrypted_msg).to_bytes(4, 'big') + encrypted_msg)
                
                
                msg_len = int.from_bytes(peer_socket.recv(4), 'big')
                encrypted_response = peer_socket.recv(msg_len)
                decrypted_response = self._aes_decrypt(encrypted_response)
                print(f"[CLIENT {self.client_id}]: Received encrypted message {i+1} ({len(decrypted_response)} chars)")
                print(f"[CLIENT {self.client_id}]: Decrypted: {decrypted_response[:50]}...")
            else:
                
                msg_len = int.from_bytes(peer_socket.recv(4), 'big')
                encrypted_msg = peer_socket.recv(msg_len)
                decrypted_msg = self._aes_decrypt(encrypted_msg)
                print(f"[CLIENT {self.client_id}]: Received encrypted message {i+1} ({len(decrypted_msg)} chars)")
                print(f"[CLIENT {self.client_id}]: Decrypted: {decrypted_msg[:50]}...")
                
                
                response_msg = f"Response to message {i+1}: " + "A" * 250
                print(f"[CLIENT {self.client_id}]: Sending encrypted message {i+1} ({len(response_msg)} chars)")
                encrypted_response = self._aes_encrypt(response_msg)
                peer_socket.sendall(len(encrypted_response).to_bytes(4, 'big') + encrypted_response)
        
        
        print(f"[CLIENT {self.client_id}]: Sending BYE")
        bye_msg = "BYE"
        encrypted_bye = self._aes_encrypt(bye_msg)
        peer_socket.sendall(len(encrypted_bye).to_bytes(4, 'big') + encrypted_bye)
        
        print(f"[CLIENT {self.client_id}]: Message exchange completed\n")



if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id> [peer_id] [peer_port]")
        print("Example: python client.py 8001")
        print("Example: python client.py 8001 8002 8002")
        sys.exit(1)
    
    client_id = int(sys.argv[1])
    client = Client(client_id, client_id)
    
    
    client.register_with_keyserver()
    
    
    if len(sys.argv) >= 4:
        peer_id = int(sys.argv[2])
        peer_port = int(sys.argv[3])
        time.sleep(2)  
        client.initiate_communication(peer_id, peer_port)
    else:
        print(f"[CLIENT {client_id}]: Waiting for incoming connections...")
        
        while True:
            time.sleep(1)