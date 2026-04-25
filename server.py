import socket
import threading

clients = []

def broadcast(data, sender):
    for c in clients:
        if c != sender:
            try:
                c.send(data)
            except:
                pass

def handle(conn):
    clients.append(conn)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            broadcast(data, conn)
    finally:
        clients.remove(conn)
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5000))
server.listen()

print("Server running.")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle, args=(conn,)).start()