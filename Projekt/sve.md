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

# spajanje klijenta i posluzitelja
1. Povezivanje
```
ssh linkPosluzitelja
```
```
$ ssh example.group.miletic.net
The authenticity of host 'example.group.miletic.net (135.181.105.39)' can't be established.
ECDSA key fingerprint is SHA256:0ru7bD+izhNW+qTNFkxqHtDoiyDRNLUHHvvuF0O0I84.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```
2. 
```
ssh student@linkPosluzitelja
```
```
$ ssh student@example.group.miletic.net
student@example.group.miletic.net's password:
```
Ako nije na vratima 22 treba navesti port
```
$ ssh -p 2223 student@example.group.miletic.net
student@example.group.miletic.net's password:
```
3. Provjera ako se spojilo (regex da trazi 400 Bad Request)
```
ssh -v -p 443 example.group.miletic.net
```