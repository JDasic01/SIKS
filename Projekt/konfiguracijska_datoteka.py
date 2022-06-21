# Imports
import base64
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
def FirstHandshakeSharedKey():
    private_key = X25519PrivateKey.generate()
    #print(private_key)
    peer_public_key = X25519PrivateKey.generate().public_key()
    shared_key = private_key.exchange(peer_public_key) # odvojit u posebnu funkciju, shared key imaju i posluzitelj i klijent
    with open('firstHandshake.txt', 'w') as f:
        f.write(str(shared_key))

    # shared key pustit ovdje, pristupit iz klijenta i posluzitelja
    # posluzitelj cita shared key iz datoteke

def FirstHandshakeData(fernet_key):
    f = open("firstHandshake.txt", "r")
    shared_key = bytes(f.read(), 'utf-8')
    key = bytes(fernet_key, 'utf-8')
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=key, # umjesto handshake data stavit fernet kljuc
    ).derive(shared_key)
    with open('firstHandshakeDerivedKey.txt', 'w') as f:
        f.write(str(derived_key))

def SecondHandshakeSharedKey():
    private_key_2 = X25519PrivateKey.generate()
    peer_public_key_2 = X25519PrivateKey.generate().public_key()
    shared_key_2 = private_key_2.exchange(peer_public_key_2)
    with open('secondHandshake.txt', 'w') as f:
        f.write(str(shared_key_2))

def SecondHandshakeData(fernet_key):
    f = open("firstHandshake.txt", "r")
    shared_key_2 = bytes(f.read(), 'utf-8')
    key = bytes(fernet_key, 'utf-8')
    derived_key_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=key,
    ).derive(shared_key_2)
    with open('secondHandshakeDerivedKey.txt', 'w') as f:
        f.write(str(derived_key_2))


# Autentifikacija poruka
# Poly1305 
from cryptography.hazmat.primitives import poly1305
def PolyKey():
    key = ChaCha20Poly1305.generate_key()
    p = poly1305.Poly1305(key) # key se generira za svaku poruku, treba biti velicine 32 bita
    p.update(b"message to authenticate")
    p.verify(b"an incorrect tag")
    p.finalize()
    return True
    

# ChaCha poly jer ovaj gore ne radi
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
def ChaChaPoly(message):
    data = message
    aad = b"slanje poruke" # nije obavezan parametar, nesto sto se salje sa porukom ali ne treba biti pod enkripcijom
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, aad)
    chacha.decrypt(nonce, ct, aad)
    return True

# Sifriranje poruka
# FERNET
# Ideja kako ovo napravit, pozovemo funkciju FernetGenerateKey kod klijenta ili kod posluzitelja ako nam treba jedan kljuc
# pozvat FernetGenerateKey i kod klijenta i kod posluzitelja ako nam treba dva kljuca
# Razmjena kljuceva preko X25519, poslat ce f iz ove gore funkcije posluzitelju i klijentu (ili svakom posebno ako treba dva kljuca)

# Problem je kako svaki put poslat encrypted_message bez spremanja u datoteku (napravit datoteku chat.txt u koju se spremaju sve poruke i onda citat iz te datoteke zadnju dodanu)
# mozda preko http post zahtjeva napravit (wsgi server/docker i poruka je slanje zahtjeva post u terminalu)
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
    print("Dešifrirana poruka je", decrypted_message) # Desifrirana poruka mora imati ispis, return nebitan jer se samo treba ispisat?

# Pseudokod za autentifikaciju
# nez 

# Pseudokod za razmjenu kljuceva
# X25519 generate private key, ispis u datoteku
# u info kod derived key ide f koji ce se koristiti za fernet

# Pseudokod za spojit Fernet i Poly
# if PolyKey is valid
#   FernetDecrypt
# else
#   Invalid Message

if __name__ == "__main__":
    fernet_key = FernetGenerateKey()
    fernet_key_string = str(fernet_key)
    FirstHandshakeSharedKey()
    FirstHandshakeData(fernet_key_string)
    SecondHandshakeSharedKey()
    SecondHandshakeData(fernet_key_string)
    # fernet proslijeden, razmjena kljuceva gotova

    #ovo isto ide u while petlju
    encrypted_message=FernetEncrypt(fernet_key)

    # spajanje poly, ovo ce bit while petlja dok klijent/posluzitelj ne prekine slanje poruka
    if (ChaChaPoly(encrypted_message)):
        FernetDecrypt(fernet_key, encrypted_message)
    else:
        print("dobili ste poruku koja nije valjana")



