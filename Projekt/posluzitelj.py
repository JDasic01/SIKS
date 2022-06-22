import konfiguracijska_datoteka

kljucic = konfiguracijska_datoteka.FernetGenerateKey() # posalji klijentu
with open('kljucic.txt', 'w') as f:
        f.write(str(kljucic))

f = open("kljucic.txt", "r")
fernet_key_string = f.read()

konfiguracijska_datoteka.SecondHandshakeSharedKey()
konfiguracijska_datoteka.SecondHandshakeData(fernet_key_string)

encrypted_message=konfiguracijska_datoteka.FernetEncrypt(kljucic) # ovo dobivamo od klijenta, kljucicKlijent ide tu

if (konfiguracijska_datoteka.ChaChaPoly(encrypted_message)):
    konfiguracijska_datoteka.FernetDecrypt(kljucic, encrypted_message)
else:
    print("dobili ste poruku koja nije valjana")


