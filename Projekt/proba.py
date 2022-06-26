from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def FirstHandshake():
    private_key = X25519PrivateKey.generate()
    peer_public_key = private_key.public_key()
    shared_key = private_key.exchange(peer_public_key) 
    return private_key, shared_key

fernet_kljuc1 = Fernet.generate_key()
n1, shared1 = FirstHandshake()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

private_key = x25519.X25519PrivateKey.generate()
private_bytes = private_key.private_bytes(

    encoding=serialization.Encoding.Raw,

    format=serialization.PrivateFormat.Raw,

    encryption_algorithm=serialization.NoEncryption()

)

private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
print(private_key)
private_key = int.from_bytes(bytes(private_key), "little")
shared1 = int.from_bytes(shared1, "little") 
shared_secret = fernet_kljuc1/n1

fernet_kljuc2 = Fernet.generate_key()
n2, shared2 = FirstHandshake()

n2 = int.from_bytes(n2, "little")
shared2 = int.from_bytes(shared2, "little") 
shared_secret2 = fernet_kljuc2/n2

if(shared_secret == shared_secret2):
    print("a")


