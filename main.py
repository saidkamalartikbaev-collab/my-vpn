import socket
import threading
import argparse
from cryptography.fernet import Fernet
import os

class VPNServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"VPN Server initialized. Encryption Key: {self.key.decode()}")

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[*] Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[+] Client connected from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("[!] Server shutting down...")
            self.server_socket.close()

    def handle_client(self, client_socket, addr):
        try:
            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break
                
                decrypted_data = self.cipher.decrypt(encrypted_data)
                print(f"[*] Received from {addr}: {decrypted_data.decode()}")
                
                response = b"[ACK] Data received"
                encrypted_response = self.cipher.encrypt(response)
                client_socket.send(encrypted_response)
        except Exception as e:
            print(f"[!] Error with client {addr}: {e}")
        finally:
            client_socket.close()
            print(f"[-] Client {addr} disconnected")

class VPNClient:
    def __init__(self, server_ip, server_port, key):
        self.server_ip = server_ip
        self.server_port = server_port
        self.cipher = Fernet(key)
        self.client_socket = None

    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            print(f"[+] Connected to VPN Server at {self.server_ip}:{self.server_port}")
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
        return True

    def send_data(self, data):
        try:
            encrypted_data = self.cipher.encrypt(data.encode())
            self.client_socket.send(encrypted_data)
            print(f"[*] Sent: {data}")
            
            encrypted_response = self.client_socket.recv(1024)
            response = self.cipher.decrypt(encrypted_response)
            print(f"[*] Received: {response.decode()}")
        except Exception as e:
            print(f"[!] Error sending data: {e}")

    def interactive_mode(self):
        print("[*] Entering interactive mode. Type 'exit' to quit.")
        while True:
            data = input("> ").strip()
            if data.lower() == 'exit':
                break
            if data:
                self.send_data(data)
        self.client_socket.close()


def main():
    parser = argparse.ArgumentParser(description='Simple VPN Application')
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='VPN mode')
    parser.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8888, help='Server port (default: 8888)')
    parser.add_argument('--server', help='Server IP for client mode')
    parser.add_argument('--key', help='Encryption key for client mode')

    args = parser.parse_args()

    if args.mode == 'server':
        server = VPNServer(args.host, args.port)
        server.start()
    
    elif args.mode == 'client':
        if not args.server or not args.key:
            print("[!] Client mode requires --server and --key arguments")
            return
        
        client = VPNClient(args.server, args.port, args.key.encode())
        if client.connect():
            client.interactive_mode()

if __name__ == '__main__':
    main()