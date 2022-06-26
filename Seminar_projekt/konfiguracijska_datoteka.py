# Fernet
from cryptography.fernet import Fernet

def FernetGenerateKey():
    key = Fernet.generate_key()
    f = Fernet(key)
    return f

def FernetEncrypt(f, msg):
    encrypted_message = f.encrypt(msg)
    return encrypted_message

def FernetDecrypt(f, msg):
    print(f.decrypt(msg))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate a private key for use in the exchange.
def GenerateX25519KeyClient():
    private_key = X25519PrivateKey.generate()
    return private_key
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
def GenerateX25519KeyServer(private_key_client, private_key_server):
    peer_public_key = private_key_server
    shared_key = private_key_client.exchange(peer_public_key)
    return shared_key
# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

# For the next handshake we MUST generate another private key.
private_key_2 = X25519PrivateKey.generate()
peer_public_key_2 = X25519PrivateKey.generate().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)
derived_key_2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key_2)