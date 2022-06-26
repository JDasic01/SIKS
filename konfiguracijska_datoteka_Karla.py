import secrets
from cryptography.fernet import Fernet
# Fernet
def FernetGenerateKey():
    key = Fernet.generate_key()
    f = Fernet(key)
    return f

def FernetEncrypt(f):
    message = bytes(input("Unos poruke: "), 'utf-8')
    encrypted_message = f.encrypt(message)
    return encrypted_message 

def FernetDecrypt(f, encrypted_message):
    decrypted_message = f.decrypt(encrypted_message)
    print(decrypted_message) 

from cryptography.hazmat.primitives import poly1305
import os
# Poly
key = secrets.token_bytes(32)
p = poly1305.Poly1305(key)
p = poly1305.Poly1305(key)
tag = poly1305.Poly1305.generate_tag(key, b"message to authenticate")
poly1305.Poly1305.verify_tag(key, b"message to authenticate", tag)

def FirstHandshakeSharedKey():
    private_key = X25519PrivateKey.generate()
    #print(private_key)
    peer_public_key = X25519PrivateKey.generate().public_key()
    shared_key = private_key.exchange(peer_public_key) # odvojit u posebnu funkciju, shared key imaju i posluzitelj i klijent
    with open('firstHandshake.txt', 'w') as f:          # umjesto pisanja u datoteku stavit u varijablu i poslat iz klijenta u posluzitelj i obrnuto
        f.write(str(shared_key))

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
    with open('firstHandshakeDerivedKey.txt', 'w') as f: # umjesto pisanja u datoteku stavit u varijablu i poslat iz klijenta u posluzitelj i obrnuto
        f.write(str(derived_key))

def SecondHandshakeSharedKey():
    private_key_2 = X25519PrivateKey.generate()
    peer_public_key_2 = X25519PrivateKey.generate().public_key()
    shared_key_2 = private_key_2.exchange(peer_public_key_2)
    with open('secondHandshake.txt', 'w') as f:         # umjesto pisanja u datoteku stavit u varijablu i poslat iz klijenta u posluzitelj i obrnuto
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
    with open('secondHandshakeDerivedKey.txt', 'w') as f: # umjesto pisanja u datoteku stavit u varijablu i poslat iz klijenta u posluzitelj i obrnuto
        f.write(str(derived_key_2))

# X.509 
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
one_day = datetime.timedelta(1, 0, 0)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
]))
builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(
    x509.SubjectAlternativeName(
        [x509.DNSName(u'cryptography.io')]
    ),
    critical=False
)
builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True,
)
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
)
isinstance(certificate, x509.Certificate)

# ove dvije linije provjerava druga strana (svaka generira ovo iznad, posalje certificate i onda bi ovo trebalo provjerit ako je valjan - nisam sigurna)
public_key = certificate.public_key()
print(isinstance(public_key, rsa.RSAPublicKey))