import os.path
from pathlib import Path

import rsa
from rsa import PublicKey, PrivateKey


def generate_key_pair(prefix_file_name: str) -> tuple[PrivateKey, PublicKey]:
    key_size = 2048 * 1  # Should be at least 2048
    (public_key, private_key) = rsa.newkeys(key_size)
    key_pem_path = Path(f"{prefix_file_name}_private.pem")
    key_pem_path.write_bytes(private_key.save_pkcs1())
    public_pem_path = Path(f"{prefix_file_name}_public.pem")
    public_pem_path.write_bytes(public_key.save_pkcs1())

    return private_key, public_key


def get_private_and_public_key(
    prefix_file_name: str,
) -> tuple[PrivateKey, PublicKey]:
    """get our pair of private and public keys"""
    if not os.path.exists(f"{prefix_file_name}_private.pem"):
        return generate_key_pair(prefix_file_name)
    private_pem_bytes = Path(f"{prefix_file_name}_private.pem").read_bytes()
    public_pem_bytes = Path(f"{prefix_file_name}_public.pem").read_bytes()
    return rsa.PrivateKey.load_pkcs1(private_pem_bytes), rsa.PublicKey.load_pkcs1(
        public_pem_bytes
    )


def deserialize_public_key(public_key: PublicKey) -> bytes:
    return public_key.save_pkcs1()


def serialize_public_key(public_key: bytes) -> PublicKey:
    return rsa.PublicKey.load_pkcs1(public_key)
