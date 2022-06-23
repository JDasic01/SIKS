import socket
import threading

HEADER =  b' ' *2048
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send():
    msg = "Klijent: " + input("Unos poruke: ")
    if msg== DISCONNECT_MESSAGE:
        send(DISCONNECT_MESSAGE)
    message = msg.encode(FORMAT)
    client.send(HEADER)
    client.send(message)
    

def recieve():
    print(client.recv(2048).decode(FORMAT))

while True:
    send()
    recieve()


# from operator import imod
# import konfiguracijska_datoteka

# import socket

# HEADER = 64
# PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER, PORT)
# FORMAT = 'utf-8'
# DISCONNECT_MESSAGE = "disconnected"

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect(ADDR)

# def send(msg):
#     message = msg.encode(FORMAT)
#     msg_length = len(message)
#     send_length = str(msg_length).encode(FORMAT)
#     send_length += b' '*(HEADER-len(send_length))
#     client.send(send_length)
#     client.send(message)
#     print(client.recv(2048).decode(FORMAT))

# # posalji kljuc
# kljucKlijent = konfiguracijska_datoteka.FernetGenerateKey() # posalji posluzitelju 
# client.send(kljucKlijent)
# # primi kljuc
# print(client.recv(2048).decode(FORMAT))
# while True:
#     poruka = input("")
#     send(poruka)



# f = open("kljucic.txt", "r")
# fernet_key_string = f.read()

# konfiguracijska_datoteka.FirstHandshakeSharedKey()
# konfiguracijska_datoteka.FirstHandshakeData(fernet_key_string)

# encrypted_message=konfiguracijska_datoteka.FernetEncrypt(kljucic) # ovo dobivamo of posluzitelja, kljucicPosluzitelj ide tu

# if (konfiguracijska_datoteka.ChaChaPoly(encrypted_message)):
#     konfiguracijska_datoteka.FernetDecrypt(kljucic, encrypted_message)
# else:
#     print("dobili ste poruku koja nije valjana")

