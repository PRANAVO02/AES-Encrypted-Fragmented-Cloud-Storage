import os
import json
import shutil
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from config import ACCESS_TOKEN, DROPBOX_FOLDER, DOWNLOAD_FOLDER, RECONSTRUCTED_FOLDER, ECC_PRIVATE_KEY_FILE

# --- Load ECC private key ---
with open(ECC_PRIVATE_KEY_FILE, "rb") as f:
    ecc_private_key = serialization.load_pem_private_key(f.read(), password=None)

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

def download_and_decrypt(filename, registry_file="manifests.json"):
    # --- Download registry ---
    metadata, res = dbx.files_download(f"{DROPBOX_FOLDER}/manifests.json")
    registry = json.loads(res.content)

    if filename not in registry:
        raise Exception(f"No manifest found for {filename}")

    manifest = registry[filename]

    # --- Decrypt AES key using ECC private key ---
    aes_key_encrypted = bytes.fromhex(manifest["aes_key_encrypted"])
    aes_key = ecc_private_key.decrypt(
        aes_key_encrypted,
        ec.ECIESHKDFRecipientInfo(algorithm=hashes.SHA256())
    )

    # --- Prepare download folder ---
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

    # --- Save reconstructed file ---
    os.makedirs(RECONSTRUCTED_FOLDER, exist_ok=True)
    reconstructed_path = os.path.join(RECONSTRUCTED_FOLDER, f"reconstructed_{filename}")
    with open(reconstructed_path, "wb") as f:
        f.write(reconstructed_data)

    print(f"✅ File reconstructed successfully as '{reconstructed_path}'")
