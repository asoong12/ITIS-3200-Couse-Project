import socket
import threading
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


aes_key = b"0123456789abcdef"           # 16 bytes for AES-128
hmac_key = b"abcdef0123456789abcdef0123456789"  # 32 bytes for HMAC-SHA256


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

def verify_hmac(data, tag):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 5000))
print("[CLIENT] Connected to server.")

# Replay protection — tracks highest sequence number seen
last_seen_seq = 0
seq_lock = threading.Lock()

def recv():
    global last_seen_seq
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            # Packet format: iv (16 bytes) | ciphertext | hmac tag (32 bytes)
            iv  = data[:16]
            tag = data[-32:]
            ct  = data[16:-32]

            # ── Integrity check ──
            if not verify_hmac(iv + ct, tag):
                print("\n[!] INTEGRITY FAILED — message was tampered with, dropping.")
                continue

            # ── Decrypt ──
            plaintext = decrypt(iv, ct).decode(errors="ignore")

            # ── Replay check ──
            try:
                seq_str, actual_msg = plaintext.split(":", 1)
                seq = int(seq_str)
            except ValueError:
                print("\n[!] Malformed message, dropping.")
                continue

            with seq_lock:
                if seq <= last_seen_seq:
                    print(f"\n[!] REPLAY DETECTED — sequence {seq} already seen, dropping.")
                    continue
                last_seen_seq = seq

            print(f"\n[MESSAGE] {actual_msg}")

        except Exception as e:
            print(f"[ERROR] {e}")
            break

send_seq = 0
send_lock = threading.Lock()

def send():
    global send_seq
    while True:
        text = input("> ")
        with send_lock:
            send_seq += 1
            seq = send_seq

        msg = f"{seq}:{text}".encode()
        iv, ct = encrypt(msg)
        tag = make_hmac(iv + ct)

        sock.send(iv + ct + tag)

threading.Thread(target=recv, daemon=True).start()
send()
