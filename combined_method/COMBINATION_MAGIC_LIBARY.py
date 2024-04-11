from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

# Generate RSA key pair
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
rsa_public_key = rsa_private_key.public_key()

# Generate ECDSA key pair
ec_private_key = ec.generate_private_key(
    ec.SECP256R1(), 
    default_backend()
)
ec_public_key = ec_private_key.public_key()

# Message to be encrypted and signed
message = b"The quick brown fox jumps over the lazy dog!"

# Sign the message using ECDSA
hash_message = hashes.Hash(hashes.SHA256(), backend=default_backend())
hash_message.update(message)
digest = hash_message.finalize()
signature = ec_private_key.sign(
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)

print("This signature yo -> ", signature)

# Combine digital signature and message into a single byte string
data_to_encrypt = signature + message

# Encrypt the combined data using RSA
cipher_combined_data = rsa_public_key.encrypt(
    data_to_encrypt,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print ("This is cypherText -> ", cipher_combined_data)

# Now you can send cipher_combined_data

# Decrypt the combined data using RSA
decrypted_combined_data = rsa_private_key.decrypt(
    cipher_combined_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print ("This is combined Plaintext -> ", decrypted_combined_data)
# Separate the digital signature and message
signature_len = len(signature)
decrypted_signature = decrypted_combined_data[:signature_len]
decrypted_message = decrypted_combined_data[signature_len:]


print ("This is decrypted signature -> ", decrypted_signature)
# Verify the signature
counter = 0
try:
    ec_public_key.verify(
        decrypted_signature,
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print("Signature is valid.")
    counter = 1
except:
    counter = 2

if counter == 2:
    print("Signature is invalid.")
else:
    print("Decrypted message:", decrypted_message.decode())
