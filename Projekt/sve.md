# Provjera
## Provjera poslužitelja 
Za SMTP preko TLS-a/SSL-a:
```
$ openssl s_client -connect example.com:465
```
## Provjera klijenta
```
$ openssl s_server -key mojkljuc.pem -cert mojcertifikat.pem -port 49152 -www
```
Nije mi jasno kako poslužitelj ima pristup ovim datotekama (.pem)

# Autentifikacija
```
RSA
```

# Razmjena ključeva
```
X25519
```