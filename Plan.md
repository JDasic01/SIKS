1. Proć kroz sve materijale sa GASERI
2. Otkrit šta je Fernet
2. Poslat mail ako moramo nadogradit na seminar iz OS jer nam pola toga nije radilo
3. Ako do sad nismo onda otkrit šta je konfiguracijska datoteka koja mora bit u projektu

### Projekt
```
Cilj projekta je ostvariti sigurno povezivanje klijenta na poslužitelja. Prilikom povezivanja klijenta i poslužitelja potrebno je provesti razmjenu ključeva, autentifikaciju obije strane i komunikaciju šifriranu razmijenjenim ključevima koja koristi autentifikaciju poruka.
```
4. Razmjena ključeva, mislim da je bilo u nekom labosu.
5. Autentikacija obje strane.
6. Klijent bi trebao imat enkripciju, poslužitelj dekripciju 
7. Provjerit ako ide između dva klijenta (onda bi onaj koji šalje poruku trebao imati enkripciju, onaj koji prima poruku dekripciju)
### Kako bi mi to trebali riješit
9. Napravit autentikaciju preko RSA
10. Razmjena ključeva - vezana za autentifikaciju ne znam što ide prvo
11. Šifriranje poruka preko Fernet
12. Provjera valjanosti poruka preko Poly1305

# Materijali
## X25519
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
## RSA
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=RSA
## Fernet
https://cryptography.io/en/latest/fernet/
## Poly1305
https://cryptography.io/en/latest/hazmat/primitives/mac/poly1305/
