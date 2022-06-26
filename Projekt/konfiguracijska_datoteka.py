# RSA
import random
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
import math
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from decimal import *

# Autentifikacija RSA
def GenerirajRSAkljuceve():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_pem = private_key.private_bytes(                                
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

    verification = public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    if(verification):
        short_message = b"0123556789"
        ciphertext = public_key.encrypt(
            short_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
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


def FernetGenerateKey():
    key = Fernet.generate_key()
    key = int.from_bytes(key, "big")
    return key 

def FernetEncrypt(f, message):
    encrypted_message = f.encrypt(message) 
    return encrypted_message 

def FernetDecrypt(f, encrypted_message):
    decrypted_message = f.decrypt(encrypted_message)
    print(decrypted_message) 


if __name__ == "__main__":

    fernet_key1 = FernetGenerateKey()
    fernet_key2 = FernetGenerateKey()
    
    q1 = X25519(fernet_key1)
    q2 = X25519(fernet_key2)

    if(fernet_key2==fernet_key1*q2):
        print("Ima nade")
