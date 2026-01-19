import base64
import hashlib
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


def sha256_hash(text: str, salt: str | None = None) -> str:
    """
    Returns SHA-256 hex digest of text (optionally salted).
    """
    data = (salt + text).encode("utf-8") if salt else text.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_fernet_key() -> str:
    """
    Generates a Fernet key (URL-safe base64) as a string.
    """
    return Fernet.generate_key().decode("utf-8")


def encrypt_symmetric(plain_text: str, key: str) -> str:
    """
    Encrypts text using Fernet symmetric encryption.
    Returns base64 token string.
    """
    f = Fernet(key.encode("utf-8"))
    token = f.encrypt(plain_text.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_symmetric(token: str, key: str) -> str:
    """
    Decrypts Fernet token back to plaintext.
    """
    f = Fernet(key.encode("utf-8"))
    plain = f.decrypt(token.encode("utf-8"))
    return plain.decode("utf-8")


@dataclass
class RSAKeyPair:
    private_pem: str
    public_pem: str


def generate_rsa_keypair() -> RSAKeyPair:
    """
    Generates RSA private/public keypair (PEM format).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return RSAKeyPair(private_pem=private_pem, public_pem=public_pem)


def rsa_encrypt(message: str, public_pem: str) -> str:
    """
    Encrypts a short message using RSA public key.
    Returns base64 ciphertext.
    """
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    ciphertext = public_key.encrypt(
        message.encode("utf-8"),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(ciphertext_b64: str, private_pem: str) -> str:
    """
    Decrypts base64 ciphertext using RSA private key.
    """
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    plain = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plain.decode("utf-8")
