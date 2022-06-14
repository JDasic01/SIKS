# Imports
from cryptography.fernet import Fernet # Fernet za sifriranje poruka
import os # za stvaranje random kljuca za Poly

# Autentifikacija
# RSA

# Razmjene kljuceva
# X25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate()

# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.

peer_public_key = X25519PrivateKey.generate().public_key()
shared_key = private_key.exchange(peer_public_key)

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

# Autentifikacija poruka
# Poly1305 
from cryptography.hazmat.primitives import poly1305
key = os.urandom(20)
p = poly1305.Poly1305(key) # key se generira za svaku poruku, treba biti velicine 32 bita
p.update(b"message to authenticate")
p.finalize()

p = poly1305.Poly1305(key) # isto kao i gore
p.update(b"message to authenticate")
p.verify(b"an incorrect tag")

# Sifriranje poruka
# FERNET

# kod klijenta i posluzitelja posebno
def FernetGenerateKey():
    key = Fernet.generate_key()
    f = Fernet(key)
# Ideja kako ovo napravit, pozovemo funkciju kod klijenta i kod posluzitelja, svaki generira svoj kljuc
# Razmjena kljuceva preko X25519, poslat ce f iz ove gore funkcije posluzitelju i klijentu

# Problem je kako svaki put poslat encrypted_message bez spremanja u datoteku (mozemo i spremit u datoteku, treba poslat mail za provjerit ako smijemo)
# mozda neki get/post/put napravit

def FernetEncrypt(f, message):
    encrypted_message = f.encrypt(message) # message mora biti u obliku b"poruka", enkripcija prima samo bitove
    # print("Šifrirana poruka je", encrypted_message)
    return encrypted_message # ovo se salje drugoj strani 

def FernetDecrypt(f, encrypted_message):
    decrypted_message = f.decrypt(encrypted_message)
    print("Dešifrirana poruka je", decrypted_message) # Desifrirana poruka mora imati ispis, return nebitan


# Pseudokod za autentifikaciju
# nez :(

# Pseudokod za razmjenu kljuceva
# X25519 generate private key, ispis u datoteku
# u info kod derived key ide f koji ce se koristiti za fernet

# Pseudokod za spojit Fernet i Poly
# if PolyKey is valid
#   FernetDecrypt
# else
#   Invalid Message



