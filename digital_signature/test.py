
import platform
from time import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from dsa import generate_dsa_key, sign_and_verify_DSA
from ecdsa import generate_ecdsa_key, sign_and_verify_ECDSA


def get_average(time: list) -> float:
    return sum(time) / len(time)

def main():
    print(platform.machine())
    print(platform.processor())
    # DSA key sizes
    dsa_key_sizes = [1024, 2048, 3072, 4096]
    
    # ECDSA curves
    ecdsa_curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]

    #DSA result containers
    dsa_kg = [[], [], [], []]
    dsa_se = [[], [], [], []]
    dsa_vd = [[], [], [], []]
    #ECDSA result containers
    ecdsa_kg = [[], [], []]
    ecdsa_se = [[], [], []]
    ecdsa_vd = [[], [], []]
    
# KEY GENERATIONS
    print("DSA Key Generation Time\n")
    for num, size in enumerate(dsa_key_sizes):
        for i in range(0, 9):
            result_time = generate_dsa_key(size)[1]
            dsa_kg[num].append(result_time)
            
    print("\nECDSA Key Generation Time\n")
    for num, curve in enumerate(ecdsa_curves):
        for i in range(0, 9):
            generated = generate_ecdsa_key(curve)
            private_key = generated[0]
            ecdsa_kg[num].append(generated[1])
        
    message = b"Hello, world!"

    print("\nDSA Signing and Verification Time:\n")
    for num, size in enumerate(dsa_key_sizes):
        for i in range(0, 9):
            private_key = generate_dsa_key(size)[0]
            if private_key:
                sign, verify = sign_and_verify_DSA(private_key, message)
                dsa_se[num].append(sign)
                dsa_vd[num].append(verify)
    print("\nECDSA Signing and Verification Time\n")
    for num, curve in enumerate(ecdsa_curves):
        for i in range(0, 9):
            private_key = generate_ecdsa_key(curve)[0]
            if private_key:
                result = sign_and_verify_ECDSA(private_key, message)
                
                ecdsa_se[num].append(result[0])
                ecdsa_vd[num].append(result[1])
                
    print("Average of each")
    print("=====[ DSA ]=====")
    print("[1024]")
    print("kg -> ", get_average(dsa_kg[0]))
    print("se -> ", get_average(dsa_se[0]))
    print("vd -> ", get_average(dsa_vd[0]))
    print("[2048]")
    print("kg -> ", get_average(dsa_kg[1]))
    print("se -> ", get_average(dsa_se[1]))
    print("vd -> ", get_average(dsa_vd[1]))
    print("[3072]")
    print("kg -> ", get_average(dsa_kg[2]))
    print("se -> ", get_average(dsa_se[2]))
    print("vd -> ", get_average(dsa_vd[2]))
    print("[4096]")
    print("kg -> ", get_average(dsa_kg[3]))
    print("se -> ", get_average(dsa_se[3]))
    print("vd -> ", get_average(dsa_vd[3]))
    
    print("=====[ ECDSA ]=====")
    print("[256]")
    print("kg -> ", get_average(ecdsa_kg[0]))
    print("se -> ", get_average(ecdsa_se[0]))
    print("vd -> ", get_average(ecdsa_vd[0]))
    print("[385]")
    print("kg -> ", get_average(ecdsa_kg[1]))
    print("se -> ", get_average(ecdsa_se[1]))
    print("vd -> ", get_average(ecdsa_vd[1]))
    print("[521]")
    print("kg -> ", get_average(ecdsa_kg[2]))
    print("se -> ", get_average(ecdsa_se[2]))
    print("vd -> ", get_average(ecdsa_vd[2]))

if __name__ == "__main__":
    main()