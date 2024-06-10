from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii, pickle, json

# Helper function to simulate the G function
def G(input_data):
    # Using HKDF to simulate G function
    derived = HKDF(input_data, 64, b'', SHA256)
    return derived[:32], derived[32:]  # Returning K and r

# Simulate the J function
def J(input_data, output_len):
    # Using SHA-256 hash function to simulate J function
    return SHA256.new(input_data).digest()[:output_len]

# K-PKE Key Generation using ECC
def k_pke_keygen():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    return public_key, private_key

# Derive AES key from ECC public key bytes
def derive_aes_key(public_key_bytes):
    aes_key = SHA256.new(public_key_bytes).digest()[:32]  # Take first 32 bytes for AES key
    return aes_key

# K-PKE Encrypt using derived AES key
def k_pke_encrypt(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# K-PKE Decrypt using derived AES key
def k_pke_decrypt(aes_key, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext

# ML-KEM Key Generation
def ml_kem_keygen():
    z = get_random_bytes(32)
    ek_pke, dk_pke = k_pke_keygen()
    ek = ek_pke
    ek_serialized = ek.export_key(format='DER')
    h_ek = SHA256.new(ek_serialized).digest()
    dk = (dk_pke, ek, h_ek, z)
    return ek, dk

def kem_key_convert(pub, pri):
    z = get_random_bytes(32)
    ek = pub
    ek_serialized = ek.export_key(format='DER')
    h_ek = SHA256.new(ek_serialized).digest()
    dk = (pri, ek, h_ek, z)
    return ek, dk

def ml_kem_encaps(ek):
    m = get_random_bytes(32)
    ek_serialized = ek.export_key(format='DER')
    K, r = G(m + SHA256.new(ek_serialized).digest())
    aes_key = derive_aes_key(ek_serialized)  # Derive AES key from serialized public key
    c = k_pke_encrypt(aes_key, m)
    
    # Debug print statements
    print(f"m: {m.hex()}")
    print(f"K: {K.hex()}")
    print(f"r: {r.hex()}")
    print(f"c: {c.hex()}")
    
    return K, c

def ml_kem_decaps(c, dk):
    dk_pke, ek, h_ek, z = dk
    ek_serialized = ek.export_key(format='DER')
    aes_key = derive_aes_key(ek_serialized)  # Derive AES key from serialized public key
    m_prime = k_pke_decrypt(aes_key, c)
    K_prime, r_prime = G(m_prime + h_ek)
    c_prime = k_pke_encrypt(aes_key, m_prime)
    K_bar = J(z + c, 32)
    
    # Debug print statements
    print(f"m_prime: {m_prime.hex()}")
    print(f"K_prime: {K_prime.hex()}")
    print(f"r_prime: {r_prime.hex()}")
    print(f"c_prime: {c_prime.hex()}")
    
    if c != c_prime:
        K_prime = K_bar
        print("Ciphertext mismatch, using K_bar")
    
    return K_prime


# def toPEM(ek):
#     ek_serialized = ek.export_key(format='PEM')
#     return ek_serialized

def dktoPEM(dk):
    dk_serialized = dk.export_key(format='PEM')
    return dk_serialized

def fromPEM(pri):
    dk=ECC.import_key(pri)
    return dk


# #def toecc(public_key_hex):
    

# # # Main simulation function
# def ml_kem_simulation():
#     pub, pri = k_pke_keygen()
#     ek, dk = kem_key_convert(pub, pri)
#     ek1, dk1 =kem_key_convert(pub, pri)

#     print(ek)
#     print(toPEM(ek))

#     print(dk)
#     print(dktoPEM(pri))
#     print(fromPEM(dktoPEM(pri)))

#     K,c = ml_kem_encaps(ek)
#     K1, c1 = ml_kem_encaps(ek)

#     K_prime = ml_kem_decaps(c,dk)
#     K1_prime= ml_kem_decaps(c,dk1)
#     # print(f"ek: ",binascii.hexlify(ek.export_key(format='DER')).decode())
#     # print(f"dk: ",binascii.hexlify(str(dk).encode()).decode())
#     if(K1_prime==K): 
#         print("True")
#     print(f"K: {K.hex()}")
#     print(f"K_prime: {K_prime.hex()}")

#     assert K == K_prime, "Shared keys do not match!"
#     print("Shared keys match!")

#     print()

# # Run the simulation
# ml_kem_simulation()

