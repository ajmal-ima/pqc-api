from pydantic import BaseModel

class EncryptRequest(BaseModel):
    public_key: str

class EncryptResponse(BaseModel):
    ciphertext: str
    shared_secret: str

class DecryptRequest(BaseModel):
    ciphertext: str

class DecryptResponse(BaseModel):
    shared_secret: str
