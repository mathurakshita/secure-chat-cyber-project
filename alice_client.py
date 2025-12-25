import socket
from Crypto.Random import random, get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES

#Get Bob's IP at runtime to establish connection
HOST = input("Enter Bob's (server) IP address: ")
PORT = 65432
bits = 2048

def sessionkey_to_aeskey(session_key):
    sk_bytes = session_key.to_bytes((session_key.bit_length() + 7) // 8, 'big')
    h = SHA256.new(sk_bytes)
    return h.digest()

def encrypt_message(aeskey, plaintext):
    cipher = AES.new(aeskey, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce + ciphertext + tag

def decrypt_message(aeskey, data):
    nonce = data[:16]
    tag = data[-16:]
    ciphertext = data[16:-16]
    cipher = AES.new(aeskey, AES.MODE_GCM, nonce=nonce)
    pt_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return pt_bytes.decode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #receive DH parameter for creating public and private keys
    p_bytes = s.recv(2048 // 8)
    p = int.from_bytes(p_bytes, 'big')
    g_bytes = s.recv(2)
    g = int.from_bytes(g_bytes, 'big')

    # Alice DH puclic and private keys for DH
    alice_private = random.randint(2, p - 2)
    alice_public = pow(g, alice_private, p)

    #receive Bob DH public key & send Alice DH public key to create session key
    bob_public_bytes = s.recv(2048 // 8)
    bob_public = int.from_bytes(bob_public_bytes, 'big')
    s.sendall(alice_public.to_bytes(bits // 8, 'big'))

    #compute session key & AES key for encrypting the messages
    alice_session_key = pow(bob_public, alice_private, p)
    aes_key = sessionkey_to_aeskey(alice_session_key)

    # RSA key for digital signature (generate & share public key)
    alice_rsakey = RSA.generate(2048)
    alice_public_key = alice_rsakey.publickey().export_key()

    #receiving Bob's publc key to be used for msg authentication by DS
    bob_key_len_bytes = s.recv(2)
    bob_key_len = int.from_bytes(bob_key_len_bytes, 'big')
    bob_public_key = s.recv(bob_key_len)
    bob_rsa_pub = RSA.import_key(bob_public_key)

    #send Alice's RSA PB key
    s.sendall(len(alice_public_key).to_bytes(2, 'big'))
    s.sendall(alice_public_key)

    print("Public key exchange done. Start chatting securely.")

    for _ in range(3):
        message = input("Alice, type your message: ")
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(alice_rsakey).sign(h)
        out_data = encrypt_message(aes_key, message)
        s.sendall(len(signature).to_bytes(2, 'big'))
        s.sendall(signature)
        s.sendall(out_data)
        #receiving Bob's DS
        sig_len_bytes = s.recv(2)
        sig_len = int.from_bytes(sig_len_bytes, 'big')
        signature_bob = s.recv(sig_len)
        #receive Bob's message and decrypt
        data = s.recv(1024)
        plaintext = decrypt_message(aes_key, data)
        h_rep = SHA256.new(plaintext.encode())
        try:
            pkcs1_15.new(bob_rsa_pub).verify(h_rep, signature_bob)
            print(f"Bob replies (signature is VALID): {plaintext}")
        except (ValueError, TypeError):
            print("Signature invalid! Message could be forged. Won't show plaintext.")

    print("Chat done. Closing connection.")
