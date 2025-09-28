import os
import json
import uuid
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, AES_KEY_FILE, FRAGMENT_FOLDER

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- AES encryption function ---
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

# --- Split file into fragments ---
def split_file(data, num_fragments=4):
    length = len(data)
    fragments = []
    base_size = length // num_fragments
    remainder = length % num_fragments
    start = 0
    for i in range(num_fragments):
        extra = 1 if i < remainder else 0
        end = start + base_size + extra
        fragments.append(data[start:end])
        start = end
    return fragments

# --- Main function for Flask ---
def encrypt_and_upload(file_path, registry_file="manifests.json"):
    filename = os.path.basename(file_path)

    # Create fragment folder if not exists
    os.makedirs(FRAGMENT_FOLDER, exist_ok=True)

    # Read file
    with open(file_path, "rb") as f:
        data = f.read()

    fragments = split_file(data, num_fragments=4)
    fragments_meta = []

    for i, fragment in enumerate(fragments):
        encrypted = aes_encrypt(fragment, aes_key)
        frag_name = f"{uuid.uuid4().hex}.frag"

        local_path = os.path.join(FRAGMENT_FOLDER, frag_name)
        with open(local_path, "wb") as f:
            f.write(encrypted)

        dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
        with open(local_path, "rb") as f:
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

        fragments_meta.append({"index": i, "name": frag_name})

    manifest = {
        "original_filename": filename,
        "total_fragments": len(fragments_meta),
        "fragments": fragments_meta,
    }

    # Load existing registry
    if os.path.exists(registry_file):
        with open(registry_file, "r") as mf:
            registry = json.load(mf)
    else:
        registry = {}

    registry[filename] = manifest

    # Save locally
    with open(registry_file, "w") as mf:
        json.dump(registry, mf, indent=2)

    # Upload registry to Dropbox
    with open(registry_file, "rb") as mf:
        dbx.files_upload(
            mf.read(),
            f"{DROPBOX_FOLDER}/manifests.json",
            mode=dropbox.files.WriteMode.overwrite
        )

    return manifest
