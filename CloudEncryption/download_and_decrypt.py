import os
import json
import shutil
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, DOWNLOAD_FOLDER, AES_KEY_FILE, RECONSTRUCTED_FOLDER

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- AES decryption function ---
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# --- Main function for Flask ---
def download_and_decrypt(filename, registry_file="manifests.json"):
    # Download registry from Dropbox
    registry_path = f"{DROPBOX_FOLDER}/manifests.json"
    metadata, res = dbx.files_download(registry_path)
    registry = json.loads(res.content)

    if filename not in registry:
        raise ValueError(f"No manifest found for '{filename}'")

    manifest = registry[filename]

    # Clear & prepare download folder
    if os.path.exists(DOWNLOAD_FOLDER):
        shutil.rmtree(DOWNLOAD_FOLDER)
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

    fragments = sorted(manifest["fragments"], key=lambda x: x["index"])
    reconstructed_data = b""

    for frag in fragments:
        frag_name = frag["name"]
        dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
        local_path = os.path.join(DOWNLOAD_FOLDER, frag_name)

        metadata, res = dbx.files_download(dropbox_path)
        with open(local_path, "wb") as f:
            f.write(res.content)

        decrypted_fragment = aes_decrypt(res.content, aes_key)
        reconstructed_data += decrypted_fragment

    os.makedirs(RECONSTRUCTED_FOLDER, exist_ok=True)
    reconstructed_filename = f"reconstructed_{filename}"
    reconstructed_path = os.path.join(RECONSTRUCTED_FOLDER, reconstructed_filename)

    with open(reconstructed_path, "wb") as f:
        f.write(reconstructed_data)

    return reconstructed_path
