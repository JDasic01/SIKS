import os
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1

key = os.urandom(20)

hotp = HOTP(key, 6, SHA1())
hotp_value0 = hotp.generate(0)
hotp_value1 = hotp.generate(1)
hotp_value2 = hotp.generate(75)

print("Jednokratne zaporke su", hotp_value0, hotp_value1, hotp_value2)
hotp.verify(hotp_value0, 0)
hotp.verify(hotp_value1, 1)
hotp.verify(hotp_value2, 75)