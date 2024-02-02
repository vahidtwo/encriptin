import requests
import rsa
from rsa import PublicKey

from utils import serialize_public_key, get_bluefish_cipher


def get_server_public_key(server_url: str) -> PublicKey:
    response = requests.get(server_url)
    public_key = response.json()["public_key"].encode("UTF-8")

    return serialize_public_key(public_key)


def rsa_send_encrypted_message(
    message: bytes, server_public_key: PublicKey, server_url: str
):
    encrypted_message = rsa.encrypt(message, server_public_key)

    requests.post(server_url, json={"msg": encrypted_message.hex()})


def bluefish_send_encrypted_message(message: bytes, server_url: str):
    cipher = get_bluefish_cipher()
    encrypted_message = b"".join(cipher.encrypt_ecb_cts(message))

    requests.post(server_url, json={"msg": encrypted_message.hex()})


def rsa_send_encrypted_file(
    file_name: str, message: bytes, server_public_key: PublicKey, server_url: str
):
    splited_message = [message[i : i + 100] for i in range(0, len(message), 100)]
    for msg in splited_message:
        encrypted_message = rsa.encrypt(msg, server_public_key)
        requests.post(server_url, files={"file": (file_name, encrypted_message)})


def bluefish_send_encrypted_file(file_name: str, message: bytes, server_url: str):
    cipher = get_bluefish_cipher()
    splited_message = [message[i : i + 100] for i in range(0, len(message), 100)]
    for msg in splited_message:
        encrypted_data = b"".join(cipher.encrypt_ecb_cts(msg))

        requests.post(server_url, files={"file": (file_name, encrypted_data.hex())})


base_url = "http://localhost:8000"


def rsa_example():
    public_key = get_server_public_key(base_url + "/public-key/")
    rsa_send_encrypted_message(
        "This is a encrypted payload".encode("UTF-8"),
        public_key,
        base_url + "/rsa/encrypt/message/",
    )
    with open("file.txt", "rb") as f:
        rsa_send_encrypted_file(
            "file.txt",
            f.read(),
            public_key,
            base_url + "/rsa/encrypt/file/",
        )
    with open("img.png", "rb") as f:
        rsa_send_encrypted_file(
            "img.png",
            f.read(),
            public_key,
            base_url + "/rsa/encrypt/file/",
        )


def aes_example():
    pass


def blue_fish_example():
    bluefish_send_encrypted_message(
        b"this is blue fish encrypt msg", base_url + "/blue-fish/encrypt/message/"
    )
    with open("file.txt", "rb") as f:
        bluefish_send_encrypted_file(
            "file.txt",
            f.read(),
            base_url + "/blue-fish/encrypt/file/",
        )
    with open("img.png", "rb") as f:
        bluefish_send_encrypted_file(
            "img.png",
            f.read(),
            base_url + "/blue-fish/encrypt/file/",
        )


def dsa_example():
    pass


if __name__ == "__main__":
    blue_fish_example()
    rsa_example()
