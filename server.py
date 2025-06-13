import socket
import threading
import queue

# Configuration
HOST = "10.0.1.40"
PORT = 8080

class ChatServer:
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(2)
        print(f"[SERVER] Listening on {host}:{port}")
        self.clients = []
        self.nicknames = {}
        self.msg_queue = queue.Queue()

    def client_thread(self, client, addr, client_idx):
        if len(self.clients) == 1:
            client.sendall(b"Initializing chat...\n")
            client.sendall(b"Waiting for peer...\n")
        else:
            # Notify both clients
            for c in self.clients:
                c.sendall(b"Peer connected! You can chat now.\n")
        while True:
            try:
                data = client.recv(4096)
                if not data:
                    break
                msg = data.decode('utf-8')
                self.msg_queue.put((client_idx, msg))
            except Exception as e:
                print(f"[ERROR] {e}")
                break
        client.close()
        self.clients.remove(client)
        print(f"[DISCONNECT] Client {addr} disconnected")

    def broadcaster(self):
        while True:
            idx, msg = self.msg_queue.get()
            sender = self.clients[idx]
            for i, c in enumerate(self.clients):
                if c != sender:
                    try:
                        c.sendall(msg.encode('utf-8'))
                    except Exception as e:
                        print(f"[ERROR] {e}")

    def run(self):
        threading.Thread(target=self.broadcaster, daemon=True).start()
        client_idx = 0
        while True:
            client, addr = self.server.accept()
            self.clients.append(client)
            print(f"[CONNECT] {addr} connected.")
            threading.Thread(target=self.client_thread, args=(client, addr, client_idx), daemon=True).start()
            client_idx += 1

if __name__ == "__main__":
    ChatServer(HOST, PORT).run()
