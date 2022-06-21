from operator import imod
import konfiguracijska_datoteka

#!/usr/bin/env python
def GaseriRsa():

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'1234')
    )

    print("Ključ je", private_key_pem)
    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

    print("Ključ je", public_key_pem)
    message = """Energični, za sve vrste egzistencije sposobni pojedinac \
    najveći je kapital i jedini temelj našeg narodnog kapitala,""".encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Potpis je", signature)
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

    print("Dešifrirana poruka je", plaintext)
    print("Poruka je jednaka početnoj?", plaintext == short_message)

kljucic = konfiguracijska_datoteka.FernetGenerateKey() # posalji posluzitelju 
with open('kljucic.txt', 'w') as f:
        f.write(str(kljucic))

f = open("kljucic.txt", "r")
fernet_key_string = f.read()

konfiguracijska_datoteka.FirstHandshakeSharedKey()
konfiguracijska_datoteka.FirstHandshakeData(fernet_key_string)

encrypted_message=konfiguracijska_datoteka.FernetEncrypt(kljucic) # ovo dobivamo of posluzitelja, kljucicPosluzitelj ide tu

if (konfiguracijska_datoteka.ChaChaPoly(encrypted_message)):
    konfiguracijska_datoteka.FernetDecrypt(kljucic, encrypted_message)
else:
    print("dobili ste poruku koja nije valjana")
