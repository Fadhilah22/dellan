import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Record the start time for key generation
start_time_keygen = time.time()

# Generate RSA key pair - template dari documentation library rsa
private_key = rsa.generate_private_key(
    public_exponent=65537, # better use this, if change must have good reason
    key_size=1024
)
public_key = private_key.public_key()

# Serialize public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Load public key 
public_key = serialization.load_pem_public_key(public_key_pem)

# Declare also digital signature pub key 

# Record the end time for key generation
end_time_keygen = time.time()

# Calculate the runtime for key generation
runtime_keygen = (end_time_keygen - start_time_keygen) * 1000
print("Runtime for key generation:", runtime_keygen, "ms")

# Convert plaintext to bytes / plaintext without dig sig
plaintext = b"The Quick Brown fox Jumps The Lazy Dog!"

# Record the start time for encryption
start_time_encrypt = time.time()

# Encrypt plaintext -> template documentation
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Record the end time for encryption
end_time_encrypt = time.time()

# Calculate the runtime for encryption
runtime_encrypt = (end_time_encrypt - start_time_encrypt) * 1000
print("Runtime for encryption:", runtime_encrypt, "ms")

# Record the start time for decryption
start_time_decrypt = time.time()

# Decrypt ciphertext
decrypted_plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Record the end time for decryption
end_time_decrypt = time.time()

# Calculate the runtime for decryption
runtime_decrypt = (end_time_decrypt - start_time_decrypt) * 1000
print("Runtime for decryption:", runtime_decrypt, "ms")

# print("Plaintext:", plaintext)
# print("Ciphertext:", ciphertext.hex())
# print("Decrypted ciphertext:", decrypted_plaintext.decode('utf-8'))