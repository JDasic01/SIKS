from socket import *
from threading import *
import konfiguracijska_datoteka

AUTH_MESSAGE = "Autentikacija preko RSA kljuceva...".encode()
class ChatThread(Thread):
    def __init__(self,con):
        Thread.__init__(self)
        self.con=con
    def run(self):
        name=current_thread().getName()
        while True:
            if name=='Sender':
                data=input('Server:')
                self.con.send(bytes(data, 'utf-8'))
            elif name=='Receiver':
                recData=self.con.recv(1024).decode()
                print('Client: ',recData)

server = socket(AF_INET, SOCK_STREAM)
server.bind(('127.0.0.1', 1234))
server.listen(2)
conn, addr = server.accept()
sender = ChatThread(conn)
sender.setName('Sender')
receiver=ChatThread(conn)
receiver.setName('Receiver')
konfiguracijska_datoteka.AutentifikacijaRSA()
sender.start()
receiver.start()