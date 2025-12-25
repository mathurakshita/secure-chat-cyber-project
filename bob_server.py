import socket
from Crypto.Util.number import getPrime
from Crypto.Random import random, get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES

def get_ip():
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    #using a public DNS server's IP (1.1.1.1) just to initiate the connection path
    public_dns = '1.1.1.1'
    
    try:
        #connect is used only to set up the routing,  no data is sent
        temp_socket.connect((public_dns, 53)) 
        
        #get the IP address of the local side of the socket
        ip_data = temp_socket.getsockname()
        #grab the actual IP address from the tuple
        ip = ip_data[0] 
        
        temp_socket.close() # Close manually instead of using 'finally'
        return ip
        
    except Exception:
        # if the connection fails (e.g., no network), just default to localhost
        temp_socket.close()
        return '127.0.0.1'

HOST = get_ip()
PORT = 65432
bits = 2048

print(f"Bob's IP is: {HOST} (share this with Alice to connect)")

def sessionkey_to_aeskey(session_key):
    sk_bytes = session_key.to_bytes((session_key.bit_length() + 7) // 8, 'big')
    h = SHA256.new(sk_bytes)
    return h.digest()

def encrypt_msgGcm(aeskey, plaintext):
    cipher = AES.new(aeskey, AES.MODE_GCM)
    ciphertxt, tag = cipher.encrypt_and_digest(plaintext.encode())
    #Note: nonce, ciphertext, and tag are concatenated for transmission
    return cipher.nonce + ciphertxt + tag

def decrypt_msgGcm(aeskey, data):
    #we know GCM uses 16-byte Nonce and 16-byte Tag, so we slice accordingly
    nonce = data[:16]
    tag = data[-16:]
    ciphertxt = data[16:-16]
    cipher = AES.new(aeskey, AES.MODE_GCM, nonce=nonce)
    pt_bytes = cipher.decrypt_and_verify(ciphertxt, tag)
    return pt_bytes.decode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Bob is waiting for Alice to connect...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by Alice at {addr}")

        # DH parameter generation & sending it over to Alice for creating public and private keys
        p = getPrime(2048)
        g = 2
        conn.sendall(p.to_bytes(bits // 8, 'big'))
        conn.sendall(g.to_bytes(2, 'big'))

        # Bob's DH public and private key for DH
        bob_private = random.randint(2, p - 2)
        bob_public = pow(g, bob_private, p)
        conn.sendall(bob_public.to_bytes(bits // 8, 'big'))

        #receive Alice DH public key key for creating a session key
        alice_public_bytes = conn.recv(2048 // 8)
        alice_public = int.from_bytes(alice_public_bytes, 'big')

        #compute session key & AES key for encrypting the messages
        bob_session_key = pow(alice_public, bob_private, p)
        aes_key = sessionkey_to_aeskey(bob_session_key)

        # generating RSA key for digital signature (generate & share public key to alice)
        bob_rsakey = RSA.generate(2048)
        bob_public_key = bob_rsakey.publickey().export_key()
        conn.sendall(len(bob_public_key).to_bytes(2, 'big'))
        conn.sendall(bob_public_key)

        #receiving Alice's public RSA key to be usedfor message authentication by DS
        alice_key_bytes = conn.recv(2)
        alice_key_len = int.from_bytes(alice_key_bytes, 'big')
        alice_public_key = conn.recv(alice_key_len)
        alice_rsa_pub = RSA.import_key(alice_public_key)

        print("Public key exchange done. Start chatting securely.")

        for _ in range(3):
            #receiving alice's digital signature
            sig_bytes = conn.recv(2)
            sig_len = int.from_bytes(sig_bytes, 'big')
            signature = conn.recv(sig_len)
            # receiving encrypted message by alice
            data = conn.recv(1024)
            plaintext = decrypt_msgGcm(aes_key, data)
            h = SHA256.new(plaintext.encode())
            try:
                pkcs1_15.new(alice_rsa_pub).verify(h, signature)
                print(f"Alice says (signature is VALID): {plaintext}")
            except (ValueError, TypeError):
                print("Signature invalid! Message could be forged. Won't show plaintext.")
                continue
            #send message to reply
            reply = input("Bob, type your reply: ")
            h_reply = SHA256.new(reply.encode())
            sig_reply = pkcs1_15.new(bob_rsakey).sign(h_reply)
            conn.sendall(len(sig_reply).to_bytes(2, 'big'))
            conn.sendall(sig_reply)
            out_data = encrypt_msgGcm(aes_key, reply)
            conn.sendall(out_data)

        print("Chat done. Closing connection.")
