from socket import *
from threading import *
import konfiguracijska_datoteka

class ChatThread(Thread):
    def __init__(self,con):
        Thread.__init__(self)
        self.con=con
    def run(self):
        name=current_thread().getName()
        while True:
            if name=='Sender':
                data = konfiguracijska_datoteka.FernetEncrypt(fernet_key_server) # Fernet enkripcija
                nonce, ct, aad, key = konfiguracijska_datoteka.ChaChaPoly(data)
                self.con.send(data)
            elif name=='Receiver':
                if(konfiguracijska_datoteka.ChaChaPolyDecrypt(nonce, ct, aad, key)):
                    recData=self.con.recv(1024).decode()
                    konfiguracijska_datoteka.FernetDecrypt(fernet_key_server, recData) # Fernet dekripcija

client = socket()
client.connect(('127.0.0.1', 4321))
sender = ChatThread(client)
sender.setName('Sender')
receiver=ChatThread(client)
receiver.setName('Receiver')

# Autentikacija RSA
private_key_client, public_key_client, private_key_pem_client, public_key_pem_client = konfiguracijska_datoteka.GenerirajRSAkljuceve()
auth = konfiguracijska_datoteka.AutentikacijaRSA(private_key_client, public_key_client)

client.send(str(private_key_client).encode())
client.send(str(public_key_client).encode())

# Razmjena ključeva X25519
# First handshake
shared_key_client = konfiguracijska_datoteka.FirstHandshakeSharedKey()
fernet_key_client = konfiguracijska_datoteka.FernetGenerateKey()
derived_key_client = konfiguracijska_datoteka.FirstHandshakeData(fernet_key_client, shared_key_client)
# Second handshake
shared_key2_client = konfiguracijska_datoteka.SecondHandshakeSharedKey()
derived_key2_client = konfiguracijska_datoteka.SecondHandshakeData(fernet_key_client, shared_key2_client)

key_exchange = True

fernet_key_server = "kljucic"

if(auth and key_exchange):
    sender.start()
    receiver.start()