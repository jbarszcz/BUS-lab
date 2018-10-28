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

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib


def main():
    data = read_file()

    zadanie_3(data)
    zadanie_4(data)


def zadanie_3(correct_data):
    print(">>> Zadanie 3 <<<:\n")
    print("Klucze i pliki poprawne:\n")

    message = correct_data

    padded_data = pad(message)

    good_key = os.urandom(32)
    wrong_key = corrupt(good_key)

    # klucz i plik poprawne

    print(f"Message {message} after padding: {padded_data}")

    encrypted_data = encrypt(padded_data, good_key)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt(encrypted_data, good_key)
    decrypted_message = unpad(decrypted_data)
    print(f"Message decrypted: {decrypted_data} => {decrypted_message}")

    # niepoprawny plik

    print("\nBłąd w pliku zaszyfrowanym (pierwszy bajt zamieniony na 0): ")

    corrupted_data = corrupt(encrypted_data)
    decrypted_corrupted_data = decrypt(corrupted_data, good_key)

    print(f"Decrypted corrupted data: {decrypted_corrupted_data}")

    # niepoprawny klucz

    print("\nBłąd w kluczu:")

    bad_decrypted_data = decrypt(encrypted_data, wrong_key)
    print(f"Message decrypted with wrong key: {bad_decrypted_data}")


def zadanie_4(data):
    print("\n>>> Zadanie 4 <<<:")

    hash = generate_hash(data)
    print(f"SHA256 hash of a file: {hash}")

    hash = generate_hash(corrupt(data))
    print(f"SHA256 hash of a corrupted file: {hash}")


def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data)

    return unpadded_data + unpadder.finalize()


def corrupt(msg_bytes):  # zamienia pierwszy bajt na 0
    array = bytearray(msg_bytes)
    if array[0] != 0:
        array[0] = 0
    else:
        array[0] = 1  # jezeli 1 bajt byl wczesniej zerem to damy tam jedynke

    return bytes(array)


def encrypt(data, key):
    iv = b'\xd0\xbc\xbe\x80\x91\x19H\xf2[\x1b\xd3 \xb5\x85\xc7h'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphered_data = encryptor.update(data) + encryptor.finalize()
    return ciphered_data


def decrypt(data, key):
    iv = b'\xd0\xbc\xbe\x80\x91\x19H\xf2[\x1b\xd3 \xb5\x85\xc7h'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data


def generate_hash(data):
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()


def read_file():
    file = open("file.txt", "rb")
    data = file.read()
    file.close()
    return data


if __name__ == "__main__":
    main()
