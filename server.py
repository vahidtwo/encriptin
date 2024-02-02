import rsa
from fastapi import FastAPI, UploadFile
from pydantic import BaseModel

from utils import get_private_and_public_key, deserialize_public_key

app = FastAPI()


class EncryptedMessage(BaseModel):
    msg: str


@app.post("/encrypt/file/")
async def create_file(file: UploadFile):
    file_data, file_name = file.file.read(), file.filename
    print(f"{file_name} : {file_data}")
    private_key = get_private_and_public_key("server")[0]

    message = rsa.decrypt(file_data, private_key)
    print(message)
    with open(f"encripted_{file_name}", "wab+") as f:
        f.write(message)


@app.post("/encrypt/message/")
async def encrypted_message(encrypted_message: EncryptedMessage):
    encrypted_message_bytes = bytes.fromhex(encrypted_message.msg)
    print(encrypted_message_bytes)
    private_key = get_private_and_public_key("server")[0]
    message = rsa.decrypt(encrypted_message_bytes, private_key)
    print(message)


@app.get("/public-key/")
async def get_public_key():
    return {
        "public_key": deserialize_public_key(get_private_and_public_key("server")[1])
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
