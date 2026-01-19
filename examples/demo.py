import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto_toolkit import (
    sha256_hash,
    generate_fernet_key,
    encrypt_symmetric,
    decrypt_symmetric,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
)

def main():
    print("== Hashing ==")
    h1 = sha256_hash("hello world")
    h2 = sha256_hash("hello world", salt="SALT123")
    print("SHA-256:", h1)
    print("SHA-256 (salted):", h2)

    print("\n== Symmetric Encryption (Fernet) ==")
    key = generate_fernet_key()
    token = encrypt_symmetric("secret message", key)
    plain = decrypt_symmetric(token, key)
    print("Key:", key)
    print("Token:", token)
    print("Decrypted:", plain)

    print("\n== Asymmetric Encryption (RSA) ==")
    kp = generate_rsa_keypair()
    cipher = rsa_encrypt("short secret", kp.public_pem)
    plain2 = rsa_decrypt(cipher, kp.private_pem)
    print("Cipher (b64):", cipher)
    print("Decrypted:", plain2)

if __name__ == "__main__":
    main()
