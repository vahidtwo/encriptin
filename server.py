import rsa
from fastapi import FastAPI, UploadFile
from pydantic import BaseModel

from utils import (
    get_private_and_public_key,
    deserialize_public_key,
    get_bluefish_cipher,
)

app = FastAPI()


class EncryptedMessage(BaseModel):
    msg: str


@app.post("/rsa/encrypt/file/")
async def create_file(file: UploadFile):
    file_data, file_name = file.file.read(), file.filename
    print(f"{file_name} : {file_data}")
    private_key = get_private_and_public_key("server")[0]

    message = rsa.decrypt(file_data, private_key)
    print(message)
    with open(f"encripted_{file_name}", "ab+") as f:
        f.write(message)


@app.post("/rsa/encrypt/message/")
async def encrypted_message(encrypted_message: EncryptedMessage):
    encrypted_message_bytes = bytes.fromhex(encrypted_message.msg)
    print(encrypted_message_bytes)
    private_key = get_private_and_public_key("server")[0]
    message = rsa.decrypt(encrypted_message_bytes, private_key)
    print(message)


@app.post("/blue-fish/encrypt/file/")
async def create_file(file: UploadFile):
    cipher = get_bluefish_cipher()

    file_data, file_name = file.file.read(), file.filename
    print(f"{file_name} : {file_data}")
    encrypted_message_bytes = bytes.fromhex(file_data.decode())

    message = cipher.decrypt_ecb_cts(encrypted_message_bytes)
    print(message)
    with open(f"encripted_blue-fish_{file_name}", "ab+") as f:
        f.write(b"".join(message))


@app.post("/blue-fish/encrypt/message/")
async def encrypted_message(encrypted_message: EncryptedMessage):
    cipher = get_bluefish_cipher()

    encrypted_message_bytes = bytes.fromhex(encrypted_message.msg)
    print(encrypted_message_bytes)
    message = cipher.decrypt_ecb_cts(encrypted_message_bytes)
    print(b"".join(message))


@app.get("/rsa/public-key/")
async def get_rsa_public_key():
    return {
        "public_key": deserialize_public_key(get_private_and_public_key("server")[1])
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
