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
                data = bytes(input(),'utf-8')
                #data = konfiguracijska_datoteka.FernetEncrypt(fernet_key_server) # Fernet enkripcija
                self.con.send(data)
            elif name=='Receiver':
                msg = self.con.recv(1024).decode()
                print("Posluzitelj: " + msg)

client = socket()
client.connect(('127.0.0.1', 1234))
sender = ChatThread(client)
sender.setName('Sender')
receiver=ChatThread(client)
receiver.setName('Receiver')

sender.start()
receiver.start()