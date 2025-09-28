import hashlib

def hash_fragment(fragment_path):
    sha = hashlib.sha256()
    with open(fragment_path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()
