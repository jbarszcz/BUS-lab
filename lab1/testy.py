import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# opening for [r]eading as [b]inary
file = open("file.txt", "rb")
corrupted_file = open("corrupted_file.txt", "rb")

correct_data = file.read()
corrupted_data = corrupted_file.read()

file.close()
corrupted_file.close()


def zadanie_1(correct_data, corrupted_data):
    print("Zadanie 3:\n")
    print("Klucze i pliki poprawne:\n")

    message = correct_data

    padded_data = pad(message)

    good_key = os.urandom(32)
    wrong_key = os.urandom(32)

    print(f"Encrypting message {message}. After padding => {padded_data}")

    encrypted_data = encrypt(padded_data, good_key)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt(encrypted_data, good_key)
    decrypted_message = unpad(decrypted_data)
    print(f"Message decrypted: {decrypted_data} => {decrypted_message}")

    bad_decrypted_data = decrypt(encrypted_data, wrong_key)
    print(f"Message decrypted with wrong key: {bad_decrypted_data}")

    print("Błąd w pliku zaszyfrowanym:")

    # corrupted_data = corrupt(encrypted_data)
    # decrypted_corrupted_data = decrypt(correct_data, good_key)
    #
    # print(f"Corrupted data: {corrupted_data}. Decrypted: {decrypted_corrupted_data}")
    # print(corrupted_data)




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
    array[0] = 0
    return bytes(array)


def encrypt(data, key):
    backend = default_backend()
    iv = b'\xd0\xbc\xbe\x80\x91\x19H\xf2[\x1b\xd3 \xb5\x85\xc7h'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphered_data = encryptor.update(data) + encryptor.finalize()
    return ciphered_data


def decrypt(data, key):
    backend = default_backend()
    iv = b'\xd0\xbc\xbe\x80\x91\x19H\xf2[\x1b\xd3 \xb5\x85\xc7h'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data


zadanie_1(correct_data, corrupted_data)
