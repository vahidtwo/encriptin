import requests
import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from rsa import PublicKey

from utils import (
    serialize_public_key,
    encrypt,
)


def get_server_public_key(server_url: str) -> PublicKey:
    response = requests.get(server_url)
    public_key = response.json()["public_key"].encode("UTF-8")

    return serialize_public_key(public_key)


def send_encrypted_message(
    message: bytes, server_public_key: PublicKey, server_url: str
):
    # encrypted_message = encrypt(message, server_public_key)
    encrypted_message = rsa.encrypt(message, server_public_key)

    requests.post(server_url, json={"msg": encrypted_message.hex()})


def send_encrypted_file(
    file_name: str, message: bytes, server_public_key: PublicKey, server_url: str
):
    # encrypted_message = encrypt(message, server_public_key)
    encrypted_message = rsa.encrypt(message, server_public_key)
    requests.post(server_url, files={"file": (file_name, encrypted_message.hex())})


if __name__ == "__main__":
    base_url = "http://localhost:8000"
    public_key = get_server_public_key(base_url + "/public-key/")
    send_encrypted_message(
        "This is a encrypted payload".encode("UTF-8"),
        public_key,
        base_url + "/encrypt/message/",
    )
    with open("file.txt", "rb") as f:
        send_encrypted_file(
            "file.txt",
            f.read(),
            public_key,
            base_url + "/encrypt/file/",
        )
    with open("img.png", "rb") as f:
        send_encrypted_file(
            "img.png",
            f.read(),
            public_key,
            base_url + "/encrypt/file/",
        )
