# import os
# from utils.file_handler import split_file_auto, merge_fragments
# from utils.crypto_aes import generate_aes_key, encrypt_fragment, decrypt_fragment
# from utils.crypto_ecc import load_public_key, load_private_key, encrypt_aes_key, decrypt_aes_key
# from utils.hash_utils import hash_fragment
# from dropbox_client import upload_fragment, download_fragment
# from utils.metadata import save_metadata, load_metadata
# from config import FRAGMENT_FOLDER, ECC_PRIVATE_KEY_PATH, ECC_PUBLIC_KEY_PATH
#
# # 1. Load ECC keys
# private_key = load_private_key(ECC_PRIVATE_KEY_PATH)
# public_key = load_public_key(ECC_PUBLIC_KEY_PATH)
#
# # 2. Select file
# file_path = input("Enter path of file to upload: ")
#
# # 3. Split file
# fragments = split_file_auto(file_path)
#
# # 4. Generate AES key
# aes_key = generate_aes_key()
#
# # 5. Encrypt fragments
# metadata = []
# for frag in fragments:
#     encrypt_fragment(frag, aes_key)
#     frag_hash = hash_fragment(frag)
#     dropbox_path = f"/fragments/{os.path.basename(frag)}"
#     upload_fragment(frag, dropbox_path)
#     metadata.append({"name": frag, "hash": frag_hash, "dropbox_path": dropbox_path})
#
# # 6. Encrypt AES key with ECC
# encrypted_aes_key, ephemeral_pub = encrypt_aes_key(aes_key, public_key)
#
# # 7. Save metadata
# save_metadata(metadata)
#
# print("Upload complete!")
#
# # -----------------
# # Retrieval Example
# # -----------------
# # metadata = load_metadata()
# # decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, ephemeral_pub, private_key)
# # for frag_info in metadata:
# #     download_fragment(frag_info["dropbox_path"], frag_info["name"])
# #     decrypt_fragment(frag_info["name"], decrypted_aes_key)
# # merge_fragments([f["name"] for f in metadata], "reconstructed_" + os.path.basename(file_path))
# # print("File reconstructed successfully!")
