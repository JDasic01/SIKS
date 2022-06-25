# RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
# X25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Fernet
from cryptography.fernet import Fernet 
# ChaChaPoly1305
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Autentifikacija RSA
def GenerirajRSAkljuceve():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_pem = private_key.private_bytes(                                #print("Ključ je", private_key_pem)
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'1234')
    )    
    
    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )
    return private_key, public_key, private_key_pem, public_key_pem

def AutentikacijaRSA(private_key, public_key):
    authorized=False
    message = "Autentikacija preko RSA kljuceva...".encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # print("Potpis: ", signature)
    verification = public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    short_message = b"0123556789"
    ciphertext = public_key.encrypt(
        short_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Šifrirana poruka je", ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if(plaintext == short_message):
        authorized = True
    return authorized

# Razmjene kljuceva X25519
def FirstHandshakeSharedKey():
    private_key = X25519PrivateKey.generate()
    peer_public_key = X25519PrivateKey.generate().public_key()
    shared_key = private_key.exchange(peer_public_key) 
    return shared_key

def FirstHandshakeData(fernet_key, shared_key):
    key = bytes(fernet_key, 'utf-8')
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=key, # umjesto handshake data stavit fernet kljuc
    ).derive(shared_key)
    return derived_key

def SecondHandshakeSharedKey():
    private_key_2 = X25519PrivateKey.generate()
    peer_public_key_2 = X25519PrivateKey.generate().public_key()
    shared_key_2 = private_key_2.exchange(peer_public_key_2)
    return shared_key_2

def SecondHandshakeData(fernet_key, shared_key_2):
    key = bytes(fernet_key, 'utf-8')
    derived_key_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=key,
    ).derive(shared_key_2)
    return derived_key_2


# Autentifikacija poruka ChaChaPoly1305
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
def ChaChaPoly(message):
    data = message
    aad = b"slanje poruke" # nije obavezan parametar, nesto sto se salje sa porukom ali ne treba biti pod enkripcijom
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, aad)
    return nonce, ct, aad, key

def ChaChaPolyDecrypt(nonce, ct, aad, key):
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct, aad)

# Sifriranje poruka
# FERNET
# Ideja kako ovo napravit, pozovemo funkciju FernetGenerateKey kod klijenta ili kod posluzitelja ako nam treba jedan kljuc
# pozvat FernetGenerateKey i kod klijenta i kod posluzitelja ako nam treba dva kljuca
# Razmjena kljuceva preko X25519, poslat ce f iz ove gore funkcije posluzitelju i klijentu (ili svakom posebno ako treba dva kljuca)

def FernetGenerateKey():
    key = Fernet.generate_key()
    f = Fernet(key)
    return f

def FernetEncrypt(f):
    message = bytes(input("Unos poruke: "), 'utf-8')
    encrypted_message = f.encrypt(message) # message mora biti u obliku b"poruka", enkripcija prima samo bitove
    # print("Šifrirana poruka je", encrypted_message) # ovdje je ispis nepotreban
    return encrypted_message # ovo se salje drugoj strani 

def FernetDecrypt(f, encrypted_message):
    decrypted_message = f.decrypt(encrypted_message)
    print(decrypted_message) 

if __name__ == "__main__":

    fernet_key = FernetGenerateKey()
    fernet_key_string = str(fernet_key)
    shared_key = FirstHandshakeSharedKey()
    FirstHandshakeData(fernet_key_string, shared_key)
    shared_key_2 = SecondHandshakeSharedKey()
    SecondHandshakeData(fernet_key_string, shared_key_2)
    # fernet proslijeden, razmjena kljuceva gotova

    #ovo isto ide u while petlju
    encrypted_message=FernetEncrypt(fernet_key)

    # spajanje poly, ovo ce bit while petlja dok klijent/posluzitelj ne prekine slanje poruka
    nonce, ct, aad, key = ChaChaPoly(encrypted_message)
    if (ChaChaPolyDecrypt(nonce, ct, aad, key)):
        FernetDecrypt(fernet_key, encrypted_message)
    else:
        print("dobili ste poruku koja nije valjana")



# Pseudokod za autentifikaciju
# napravit public key u posluzitelju i u klijentu

# Pseudokod za razmjenu kljuceva
# X25519 generate private key, ispis u datoteku
# u info kod derived key ide f koji ce se koristiti za fernet

# Pseudokod za spojit Fernet i Poly
# if PolyKey is valid
#   FernetDecrypt
# else
#   Invalid Message