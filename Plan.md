1. Proć kroz sve materijale sa GASERI (Korak 1. i 2. možemo preskočit i gledat samo u Materijali.md, ostalo je skoro sve vezano za docker i MariaDb koje ne znam ako treba koristit)
2. Otkrit šta je Fernet
2. Poslat mail ako moramo nadogradit na seminar iz OS jer nam pola toga nije radilo
3. Ako do sad nismo onda otkrit šta je konfiguracijska datoteka koja mora bit u projektu (nismo :( )

### Projekt
```
Cilj projekta je ostvariti sigurno povezivanje klijenta na poslužitelja. Prilikom povezivanja klijenta i poslužitelja potrebno je provesti razmjenu ključeva, autentifikaciju obije strane i komunikaciju šifriranu razmijenjenim ključevima koja koristi autentifikaciju poruka.
```
4. Razmjena ključeva, mislim da je bilo u nekom labosu. (Nisam sigurna da ovo treba, zadnji link sa GASERI u Materijali.md trebamo napravit po uputama pa mijenjat šta trebamo)
5. Autentikacija obje strane.
6. Klijent bi trebao imat enkripciju, poslužitelj dekripciju (Ovo je krivo jer bi po tome klijent dobivao samo poruke u enkripciji, znači obje strane bi trebale imat oboje)
7. Provjerit ako ide između dva klijenta (onda bi onaj koji šalje poruku trebao imati enkripciju, onaj koji prima poruku dekripciju) (Ne ide, u zadatku je napisano da ono što piše kod klijenta je poslao poslužitelj, a ono što piše kod poslužielja je poslao klijent)
### Kako bi mi to trebali riješit
9. Napravit autentikaciju preko RSA (mislim da je to isto kao u materijalima)
10. Razmjena ključeva - vezana za autentikaciju ne znam što ide prvo
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

Ako budemo imali vremena ja bi možda napravila neko grafičko sučelje za aplikaciju ali ne znam ako to treba ili pišemo u terminalu sve poruke.
