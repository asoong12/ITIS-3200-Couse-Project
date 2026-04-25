import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 5000))

print("[ATTACKER] listening...\n")

while True:
    data = sock.recv(4096)
    print("[RAW DATA]", data)