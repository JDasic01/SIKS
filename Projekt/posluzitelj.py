from socket import *
from threading import *
import konfiguracijska_datoteka

AUTH_MESSAGE = "Autentikacija preko RSA kljuceva...".encode()
HEADER_PORUKA =  b'32862'
HEADER_AUTH = b'autentifikacija'
HEADER_KEY_EXCHANGE = b'key-exchange'
FORMAT = 'utf-8'
class ChatThread(Thread):
    def __init__(self,con):
        Thread.__init__(self)
        self.con=con
    def run(self):
        name=current_thread().getName()
        while True:
            if name=='Sender':
                data=bytes(input(), FORMAT)
                self.con.send(HEADER_PORUKA)
                self.con.send(data)
            elif name=='Receiver':
                msg = self.con.recv(1024).decode()
                print("Klijent: " + msg)


server = socket(AF_INET, SOCK_STREAM)
server.bind(('127.0.0.1', 1234))
server.listen(2)
conn, addr = server.accept()

sender = ChatThread(conn)
sender.setName('Sender')
receiver=ChatThread(conn)
receiver.setName('Receiver')

sender.start()
receiver.start()