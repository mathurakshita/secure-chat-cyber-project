# secure-chat-cyber-project
Project to connect 2 systems securely using DH and also to send encrypted messages over the secured network
<br>
<br>
<b>Overview:</b> <br>
A python based secure messaging system using Diffie-Hellman (DH) for key exchange, AES-GCM for
message encryption, and RSA digital signatures to ensure confidentiality, integrity and authentication
between the two systems over TCP sockets. <br>
Security Architecture: <br>
Step 1: Key Exchange [Diffie-Hellman] <br>
Step 2: Symmetric Encryption Setup [AES-GCM] <br>
Step 3: Authentication [RSA Digital Signatures] <br>
<br>
<br>
<b>Summary of the Security Architecture: </b><br>
Confidentiality is initially established using the Diffie-Hellman key exchange to derive a shared
secret session key between the two parties (Alice and Bob) without any full key transmission
that could be intercepted by eavesdroppers. <br>
This shared secret is subsequently hashed to produce the 256-bit AES key utilized within the
AES-GCM cipher suite. AES-GCM facilitates message encryption and concurrently assures
data integrity by affixing authentication tags, leveraging distinct nonces for every round of
communication. <br>
Furthermore, to provide irrefutable sender authenticity, both parties exchange their RSA public
keys. Each message's hash is digitally signed by the sender, and the recipient is required to
verify this signature before accepting the message, thereby eliminating the risk of tampering or
forgery.
<br>
<br>
<b>Installation and Execution:</b>
<br>
To install (pre-requisites) <br>
“pip install pycryptodome” <br>

To run:<br>
1.Running Locally (Same Machine):<br>
Terminal 1: <b>python3 bob_server.py</b> <br>
Terminal 2: <b>python3 alice_client.py</b> <br>

2.Running on Different Machines: <br>
Share Bob’s IP address with Alice as fetched to build the connection <br>
Ensure the port 65432 is open on the network <br>
Run Bob’s code first using <b>python3 bob_server.py</b> and then Alice’s <b>python3 alice_client.py</b> <br>
<br>
<br>
<b>Code Structure: </b><br>
<i>bob_server.py : </i><br>
Listens on the HOST(IP) and PORT <br>
Initiates DH parameter generation <br>
Receives first message, verifies signature, decrypts, responds <br>
Loop: Receive → Verify → Decrypt → Reply (Encrypt & Sign) <br>
<br>
<i>alice_client.py : </i><br>
Connects to the server <br>
Receives DH parameter and Bob’s public keys <br>
Initiates message exchange: Send (Sign & Encrypt) → Receive (Verify and Decrypt) <br>
Loop: Send → Receive <br>
