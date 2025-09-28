from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_fragment(fragment_path, aes_key):
    with open(fragment_path, "rb") as f:
        data = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    with open(fragment_path, "wb") as f:
        f.write(encrypted_data)

def decrypt_fragment(fragment_path, aes_key):
    with open(fragment_path, "rb") as f:
        data = f.read()
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    with open(fragment_path, "wb") as f:
        f.write(decrypted_data)
