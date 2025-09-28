from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_aes_key(aes_key, public_key):
    # Simple ECC-based key wrapping using ECDH + AES
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"keywrap").derive(shared_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_key = iv + encryptor.update(aes_key) + encryptor.finalize()
    return encrypted_key, ephemeral_key.public_key()

def decrypt_aes_key(encrypted_key, ephemeral_public_key, private_key):
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"keywrap").derive(shared_key)
    iv = encrypted_key[:16]
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    aes_key = decryptor.update(encrypted_key[16:]) + decryptor.finalize()
    return aes_key
