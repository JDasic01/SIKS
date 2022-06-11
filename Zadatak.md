# Sadržaj projekta
Cilj projekta je ostvariti sigurno povezivanje klijenta na poslužitelja. Prilikom povezivanja klijenta i poslužitelja potrebno je provesti razmjenu ključeva, autentifikaciju obije strane i komunikaciju šifriranu razmijenjenim ključevima koja koristi autentifikaciju poruka.

## Vaš projekt treba sadržavati:
```
Klijentsku skriptu
Korisničku skriptu
Konfiguracijsku datoteku
Dokumentaciju
```
## Python moduli koje se preporuča koristiti:
```
os
sys
sockets
pyca/cryptography
```
## Autentifikacija:
```
RSA
```
## Razmjene ključeva:
```
X25519
```
## Autentifikacija poruka:
```
Poly1305
```
### Za šifriranje poruka u komunikaciji iskoristite **Fernet**.

## Način rada
U procesu autentifikacije klijent prvo provjerava identitet poslužitelja, a zatim poslužitelj provjerava identitet klijenta. Ako je provjera uspješna, prelazi se na razmjenu ključeva u kojoj se dogovara ključ za šifriranje poruka.

Klijent i poslužitelj realiziraju aplikaciju za chat; tijekom rada klijentska i poslužiteljska strana šalju tekst koji korisnik unese onoj drugoj strani.

Porukama koje se prenose u komunikaciji se dodaje autentifikacijski kod na strani pošiljatelja i vrši se njegova provjera na strani primatelja.