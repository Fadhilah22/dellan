from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
import time

start_keypair = time.time()

# Generate RSA key pair
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_public_key = rsa_private_key.public_key()

# Generate ECDSA key pair
ec_private_key = ec.generate_private_key(
    ec.SECP384R1()
)
ec_public_key = ec_private_key.public_key()

end_keypair = time.time()

keypair_time = (end_keypair - start_keypair) * 1000

# Message to be encrypted and signed
message = b"The quick brown fox jumps over the lazy dog!"

start_sign_n_enc = time.time()

# Sign the message using ECDSA
hash_message = hashes.Hash(hashes.SHA256())
hash_message.update(message)
digest = hash_message.finalize()
signature = ec_private_key.sign(
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256()))
)

# Combine digital signature and message into a string
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

end_sign_n_enc = time.time()
sign_enc = (end_sign_n_enc - start_sign_n_enc) * 1000

start_dec_verify = time.time()

# Decrypt the combined data using RSA
decrypted_combined_data = rsa_private_key.decrypt(
    cipher_combined_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# seperating the signature and ciphertext
signature_len = len(signature)
decrypted_signature = decrypted_combined_data[:signature_len]
decrypted_message = decrypted_combined_data[signature_len:]

# Verifying the signature
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

end_dec_verify = time.time()

dec_verify_time = (end_dec_verify - start_dec_verify) * 1000

# if signature is found invalid, we wont decypher the ciphertext

print("Key generation runtime -> ", keypair_time ,"ms")
print("Signing and encrpyting runtime -> ", sign_enc ,"ms")
print("Decrpyt and verify runtime -> ", dec_verify_time ,"ms")

if counter == 2:
    print("Signature is invalid.")
else:
    print("Decrypted message:", decrypted_message.decode())
