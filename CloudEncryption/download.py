
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

# --- Download registry (manifests.json) ---
manifest_path = f"{DROPBOX_FOLDER}/manifests.json"
metadata, res = dbx.files_download(manifest_path)
registry = json.loads(res.content)

# --- Show available files ---
print("\n📂 Available files in registry:")
for fname in registry.keys():
    print(" -", fname)

# --- Ask user which file to reconstruct ---
target_filename = input("\nEnter filename to reconstruct: ").strip()

if target_filename not in registry:
    print(f"❌ No manifest found for {target_filename}")
    exit()

manifest = registry[target_filename]
print("✅ Manifest loaded for:", target_filename)

# --- Clear & prepare download folder ---
if os.path.exists(DOWNLOAD_FOLDER):
    shutil.rmtree(DOWNLOAD_FOLDER)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# --- AES decrypt ---
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# --- Download fragments according to manifest ---
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
    print(f"Downloaded + Decrypted {frag_name}")

# --- Save reconstructed file ---
os.makedirs(RECONSTRUCTED_FOLDER, exist_ok=True)

original_filename = manifest["original_filename"]
reconstructed_filename = f"reconstructed_{original_filename}"
reconstructed_path = os.path.join(RECONSTRUCTED_FOLDER, reconstructed_filename)

with open(reconstructed_path, "wb") as f:
    f.write(reconstructed_data)

print(f"\n✅ File reconstructed successfully as '{reconstructed_path}'")
