import socket
import threading
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

aes_key = b"0123456789abcdef"
hmac_key = b"abcdef0123456789abcdef0123456789"


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


print("\n[ATTACKER] Select attack mode:")
print("  1. Passive intercept     — read raw encrypted traffic")
print("  2. Message tampering     — corrupt ciphertext in transit")
print("  3. Replay attack         — capture and resend a valid packet")
print("  4. Leaked key            — decrypt and forge messages with stolen keys")
choice = input("Enter choice (1-4): ").strip()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 5000))
print(f"\n[ATTACKER] Connected to server. Listening for traffic...\n")

captured_packet = None  # used for replay attack

def attack_loop():
    global captured_packet

    while True:
        data = sock.recv(4096)
        if not data:
            break

        iv  = data[:16]
        tag = data[-32:]
        ct  = data[16:-32]

        print(f"\n[ATTACKER] Packet received ({len(data)} bytes)")

        # Mode 1: Passive intercept
        if choice == "1":
            print(f"[INTERCEPT] Raw encrypted bytes: {data.hex()[:80]}...")
            print("[INTERCEPT] Cannot read — AES encryption prevents plaintext access.")

        # Mode 2: Message tampering 
        elif choice == "2":
            print("[TAMPER] Corrupting ciphertext before forwarding...")
            corrupted_ct = b"\x00" * len(ct)           # zero out the ciphertext
            tampered = iv + corrupted_ct + tag          # HMAC tag is now invalid
            sock.send(tampered)
            print("[TAMPER] Tampered packet sent — receiver's HMAC check will fail.")

        # Mode 3: Replay attack 
        elif choice == "3":
            if captured_packet is None:
                captured_packet = data
                print("[REPLAY] Packet captured. Waiting 3 seconds then replaying...")
                threading.Timer(3.0, replay).start()
            else:
                print("[REPLAY] Additional packet received (ignoring — already have one).")

        # Mode 4: Leaked key 
        elif choice == "4":
            print("[LEAKED KEY] Decrypting intercepted message with stolen keys...")
            try:
                plaintext = decrypt(iv, ct).decode(errors="ignore")
                print(f"[LEAKED KEY] Attacker reads: '{plaintext}'")

                # Forge a new message with a valid HMAC
                fake_msg = b"999:Send $9999 to attacker account"
                fake_iv, fake_ct = encrypt(fake_msg)
                fake_tag = make_hmac(fake_iv + fake_ct)
                sock.send(fake_iv + fake_ct + fake_tag)
                print("[LEAKED KEY] Forged message sent with valid HMAC tag.")
            except Exception as e:
                print(f"[ERROR] {e}")

def replay():
    print("\n[REPLAY] Replaying captured packet now...")
    sock.send(captured_packet)
    print("[REPLAY] Packet replayed — check if receiver detects the duplicate sequence number.")

threading.Thread(target=attack_loop, daemon=True).start()

# Keep main thread alive
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\n[ATTACKER] Exiting.")
    sock.close()
