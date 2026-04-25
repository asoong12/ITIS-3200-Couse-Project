
# DO NOT USE!!!

from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Key Derivation
def derive_keys(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    )
    key = hkdf.derive(shared_key)
    return key[:16], key[16:]

# Encryption / Decryption
def encrypt(aes_key, msg):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    enc = cipher.encryptor()
    return iv, enc.update(msg) + enc.finalize()

def decrypt(aes_key, iv, ct):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

# HMAC
def make_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(key, data, tag):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except:
        return False

# RSA (Authentication)
def generate_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Setup Users
params = dh.generate_parameters(generator=2, key_size=2048)

A_dh_priv = params.generate_private_key()
A_dh_pub = A_dh_priv.public_key()
A_rsa = generate_rsa()

B_dh_priv = params.generate_private_key()
B_dh_pub = B_dh_priv.public_key()
B_rsa = generate_rsa()

A_pub_rsa = A_rsa.public_key()
B_pub_rsa = B_rsa.public_key()

# Attacker Setup
M_dh_priv = params.generate_private_key()
M_dh_pub = M_dh_priv.public_key()

# USER MENU
print("\nSelect Attack Mode:")
print("1. No Attack (Secure)")
print("2. MITM Attempt")
print("3. Message Tampering")
print("4. Replay Attack")
print("5. Leaked Key Attack")

choice = input("Enter choice: ")

# Secure Key Exchange
A_sig = sign(A_rsa, A_dh_pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

B_sig = sign(B_rsa, B_dh_pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Man in the middle
if choice == "2":
    print("\n[ATTACK] MITM attempting key substitution...")
    intercepted_pub = M_dh_pub
    intercepted_sig = b"fake_signature"
else:
    intercepted_pub = B_dh_pub
    intercepted_sig = B_sig

# Verify signature
valid = verify_signature(
    B_pub_rsa,
    intercepted_sig,
    intercepted_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

if not valid:
    print("Attack detected! Key exchange aborted.")
    exit()

shared = A_dh_priv.exchange(intercepted_pub)
aes_key, hmac_key = derive_keys(shared)

# Replay Protection
sequence_number = 1
last_seen_sequence = 0

# Send Message
message = f"{sequence_number}:Transfer $1000".encode()

iv, ct = encrypt(aes_key, message)
tag = make_hmac(hmac_key, iv + ct)

# Save original for replay
original_packet = (iv, ct, tag)

# ATTACK SIMULATION
if choice == "3":
    print("\n[ATTACK] Message tampering...")
    ct = b"tampered"

elif choice == "4":
    print("\n[ATTACK] Replay attack...")
    iv, ct, tag = original_packet  # resend old packet

elif choice == "5":
    print("\n[ATTACK] Leaked key scenario...")
    attacker_aes = aes_key
    attacker_hmac = hmac_key

    stolen = decrypt(attacker_aes, iv, ct)
    print("Attacker reads:", stolen.decode())

    fake_msg = b"999:Send $9999 to attacker"
    iv, ct = encrypt(attacker_aes, fake_msg)
    tag = make_hmac(attacker_hmac, iv + ct)

# Receive Message
if verify_hmac(hmac_key, iv + ct, tag):
    decrypted = decrypt(aes_key, iv, ct)
    text = decrypted.decode(errors="ignore")

    seq = int(text.split(":")[0])

    if seq <= last_seen_sequence:
        print("Replay detected! Message rejected.")
    else:
        last_seen_sequence = seq
        print("\nMessage accepted:", text)

else:
    print("\nIntegrity check failed!")