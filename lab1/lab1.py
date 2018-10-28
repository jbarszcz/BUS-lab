import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random

'''
W wybranym języku programowania (C/C++/C#, java, python, javascript,:) wykonać:
• Cztery działania na małych liczbach z wykorzystaniem procedur działania
dokładnego dla wielkich liczb (p <100)
• Cztery działania na dużych liczbach (dodawanie, odejmowanie, mnożenie,
obliczanie odwrotności modulo p, 1024 bity)
• Wykonanie szyfrowania i odszyfrowania pliku algorytmem symetrycznym
o Klucze i pliki poprawne
o Błąd w pliku zaszyfrowanym
o Błąd w kluczu przy odszyfrowaniu
• Obliczenie skrótu z pliku i sprawdzenie poprawności
o Pliki poprawne
o Plik uszkodzony/zmieniony 

'''

# zadanie 1

# zadanie 2

# zadanie 3
#
# backend = default_backend()
# key = os.urandom(32)
# wrong_key = os.urandom(32)
# iv = os.urandom(16)
# cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret messagde") + encryptor.finalize()
# decryptor = cipher.decryptor()
# print(decryptor.update(ct) + decryptor.finalize())


key = Fernet.generate_key()
wrong_key = Fernet.generate_key()

message = "no witam".encode()

f = Fernet(key)
encrypted_message = f.encrypt(message)

f2 = Fernet(wrong_key)

good_encrypted = f.decrypt(encrypted_message)
bad_encrypted = f2.decrypt(encrypted_message)

print(good_encrypted)
print(bad_encrypted)
