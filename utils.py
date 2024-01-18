import os.path
from pathlib import Path

import rsa
from cryptography.hazmat.primitives import hashes, serialization

# from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from rsa import PublicKey, PrivateKey


def generate_key_pair(prefix_file_name: str) -> tuple[PrivateKey, PublicKey]:
    key_size = 2048 * 11  # Should be at least 2048
    (public_key, private_key) = rsa.newkeys(key_size)  #
    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,  # Do not change
    #     key_size=key_size,
    # )
    #
    # public_key = private_key.public_key()
    #
    # key_pem_bytes = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,  # PEM Format is specified
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption(),
    # )
    #
    # public_pem_bytes = public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo,
    # )

    key_pem_path = Path(f"{prefix_file_name}_private.pem")

    # key_pem_path.write_bytes(key_pem_bytes)
    key_pem_path.write_bytes(private_key.save_pkcs1())
    # Filename could be anything
    public_pem_path = Path(f"{prefix_file_name}_public.pem")
    # public_pem_path.write_bytes(public_pem_bytes)
    public_pem_path.write_bytes(public_key.save_pkcs1())

    return private_key, public_key


def encrypt(message: bytes, public_key: RSAPublicKey):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(message_encrypted: bytes, private_key: RSAPrivateKey):
    message_decrypted = private_key.decrypt(
        message_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return message_decrypted


def get_private_and_public_key(
    prefix_file_name: str,
) -> tuple[PrivateKey, PublicKey]:
    """get our pair of private and public keys"""
    if not os.path.exists(f"{prefix_file_name}_private.pem"):
        return generate_key_pair(prefix_file_name)
    private_pem_bytes = Path(f"{prefix_file_name}_private.pem").read_text()
    public_pem_bytes = Path(f"{prefix_file_name}_public.pem").read_text()
    return rsa.PrivateKey.load_pkcs1(private_pem_bytes), rsa.PublicKey.load_pkcs1(
        public_pem_bytes
    )

    # return serialize_private_key(private_pem_bytes), serialize_public_key(
    #     public_pem_bytes
    # )


# def deserialize_public_key(public_key: RSAPublicKey) -> bytes:
#     return public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     )
def deserialize_public_key(public_key: PublicKey) -> bytes:
    return public_key.save_pkcs1()


def serialize_public_key(public_key: bytes) -> PublicKey:
    #     return serialization.load_pem_public_key(data=public_key)
    return rsa.PublicKey.load_pkcs1(public_key)


def deserialize_private_key(public_key: RSAPrivateKey) -> bytes:
    return public_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_private_key(private: bytes) -> RSAPrivateKey:
    return serialization.load_pem_private_key(data=private, password=None)
