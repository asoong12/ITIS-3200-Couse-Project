# Secure Real-Time Messaging System
### ITIS 3200

A real-time encrypted messaging application that demonstrates AES-CFB encryption, HMAC-SHA256 integrity verification, and sequence-number-based replay protection over an untrusted network.

---

## Requirements

```
pip install cryptography
```

Python 3.8 or higher.

---

## Running the Secure System (Success Case)

Open **three terminal windows** and run in this order:

**Terminal 1 — Start the server:**
```
python server.py
```

**Terminal 2 — Connect first client:**
```
python client.py
```

**Terminal 3 — Connect second client:**
```
python client.py
```

Type messages in either client terminal. The other client will receive them decrypted. All messages are encrypted with AES-CFB and authenticated with HMAC-SHA256. Sequence numbers prevent replay.

---

## Running the Attack / Failure Cases

Start the server and **one** client first (Terminals 1 and 2 above).  
Then in Terminal 3, run the attacker:

```
python attacker.py
```

You will see a menu:

```
1. Passive intercept     — read raw encrypted traffic

2. Message tampering     — corrupt ciphertext in transit

3. Replay attack         — capture and resend a valid packet

4. Leaked key            — decrypt and forge messages with stolen keys
```

### What each attack demonstrates


 1.  Passive intercept - Attacker prints raw bytes — cannot read content. AES prevents it. 
 
 2.  Message tampering - Receiver prints `INTEGRITY FAILED` and drops the message. HMAC catches it. 
 
 3.  Replay attack - Attacker replays a captured packet. Receiver prints `REPLAY DETECTED` and drops it. Sequence numbers catch it. 
 
 4.  Leaked key - Attacker decrypts the message and sends a forged one with a valid HMAC tag — showing that key secrecy is a prerequisite for all other protections. 

---

## File Overview


 `server.py` - TCP server — accepts connections and broadcasts messages between clients 
 `client.py` - Client — encrypts outgoing messages, verifies and decrypts incoming messages, detects replays 
 `attacker.py` - Attacker simulation — connects to server and demonstrates four attack scenarios 
 `draft.py` - Early prototype with DH + RSA key exchange (not used in final demo) 

---

## How the Mechanisms Are Implemented

Encryption (AES-CFB): Every message is encrypted with a 16-byte AES key in CFB mode. A fresh random 16-byte IV is generated per message and prepended to the ciphertext. The receiver uses the IV to decrypt.

Integrity (HMAC-SHA256): A 32-byte HMAC tag is computed over `iv + ciphertext` using a separate HMAC key and appended to every packet. The receiver recomputes the tag and rejects the message if it does not match.

**Replay protection (Sequence numbers):** Each message is prefixed with a monotonically increasing sequence number before encryption (e.g. `3:hello`). The receiver tracks the last accepted sequence number and rejects any message whose number is not strictly greater.

Packet format:
```
[ IV (16 bytes) ][ Ciphertext (variable) ][ HMAC tag (32 bytes) ]
```
