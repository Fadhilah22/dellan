from time import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding


def generate_ecdsa_key(curve):
    try:
        start_time = time()
        private_key = ec.generate_private_key(curve)
        end_time = time()
        elapsed = end_time - start_time
        print(f"ECDSA-{curve.name} Key Generation Time: {end_time - start_time:.6f} seconds")
        return [private_key, elapsed]
    except Exception as e:
        print(f"Error generating ECDSA-{curve.name} key: {e}")
        
def sign_and_verify_ECDSA(private_key, message):
    try:
        start_time = time()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_time = time()
        sign_elapsed = end_time - start_time
        print(f"Signing Time: {end_time - start_time:.6f} seconds")
        
        public_key = private_key.public_key()
        
        start_verify_time = time()
        public_key.verify(signature, message, signature_algorithm=ec.ECDSA(hashes.SHA256()))
        end_verify_time = time()
        verify_elapsed = end_verify_time - start_verify_time
        print(f"Verification Time: {end_verify_time - start_verify_time:.6f} seconds")
        
        return [sign_elapsed, verify_elapsed]
    except InvalidSignature:
        print("Invalid Signature: Signature verification failed.")
    except Exception as e:
        print(f"Error signing or verifying message: {e}")