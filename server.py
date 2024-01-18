import rsa
from fastapi import FastAPI, UploadFile
from pydantic import BaseModel

from utils import get_private_and_public_key, deserialize_public_key, decrypt

app = FastAPI()


class EncryptedMessage(BaseModel):
    msg: str


@app.post("/encrypt/file/")
async def create_file(file: UploadFile):
    file_data, file_name = file.file.read(), file.filename
    print(f"{file_name} : {file_data}")
    private_key = get_private_and_public_key("server")[0]

    # message = decrypt(bytes.fromhex(file_data), private_key)
    message = rsa.decrypt(file_data, private_key)
    print(message)
    with open(f"encripted_{file_name}", "w") as f:
        f.writelines(message.decode("UTF-8"))


@app.post("/encrypt/message/")
async def encrypted_message(encrypted_message: EncryptedMessage):
    encrypted_message_bytes = bytes.fromhex(encrypted_message.msg)
    print(encrypted_message_bytes)
    private_key = get_private_and_public_key("server")[0]
    message = decrypt(encrypted_message_bytes, private_key)
    print(message)


@app.post("/encrypt/file/")
async def encrypted_message(encrypted_message: EncryptedMessage):
    encrypted_message_bytes = bytes.fromhex(encrypted_message.msg)
    print(encrypted_message_bytes)
    private_key = get_private_and_public_key("server")[0]
    message = decrypt(encrypted_message_bytes, private_key)
    print(message)


@app.get("/public-key/")
async def get_public_key():
    _, pub_key = get_private_and_public_key("server")
    return {"public_key": deserialize_public_key(pub_key)}
