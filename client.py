import socket
import threading
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# DEMO KEYS 
# (USE FOR LEAKED KEYS)
aes_key = b"0123456789abcdef"
hmac_key = b"abcdef0123456789abcdef0123456789"

# Crypto
def encrypt(msg):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    ct = cipher.encryptor().update(msg)
    return iv, ct

def decrypt(iv, ct):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    return cipher.decryptor().update(ct)

def make_hmac(data):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify(data, tag):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except:
        return False

# Network
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 5000))

print("Connected")


def recv():
    while True:
        data = sock.recv(4096)

        iv = data[:16]
        tag = data[-32:]
        ct = data[16:-32]

        if verify(iv + ct, tag):
            msg = decrypt(iv, ct).decode(errors="ignore")
            print("\n[RECIVED MESSAGE]", msg)
        else:
            print("\n[TAMPERED MESSAGE]")

seq = 0

def send():
    global seq
    while True:
        text = input("> ")
        seq += 1

        msg = f"{seq}:{text}".encode()
        iv, ct = encrypt(msg)
        tag = make_hmac(iv + ct)

        sock.send(iv + ct + tag)

threading.Thread(target=recv, daemon=True).start()
send()