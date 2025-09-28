from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# Create keys folder if it doesn't exist
os.makedirs("keys", exist_ok=True)

# Generate private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Generate public key
public_key = private_key.public_key()

# Save private key
with open("keys/private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
# Generate AES-256 key
import os

aes_key = os.urandom(32)

# Save AES key
with open("keys/aes_key.bin", "wb") as f:
    f.write(aes_key)

print("AES-256 key generated and saved as 'keys/aes_key.bin'")

# Save public key
with open("keys/public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("ECC key pair generated successfully in 'keys/' folder!")
