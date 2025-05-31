from fastapi import FastAPI, HTTPException
from app.schemas import EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse
import oqs
import base64

app = FastAPI()

kem = oqs.KeyEncapsulation('Kyber512')
public_key = kem.generate_keypair()

@app.get("/")
def read_root():
    return {"message": "PQC API is running."}

@app.post("/generate-key")
def generate_key():
    global public_key
    public_key = kem.generate_keypair()
    return {"public_key": base64.b64encode(public_key).decode()}

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_key(data: EncryptRequest):
    try:
        pubkey_bytes = base64.b64decode(data.public_key)
        ciphertext, shared_secret = kem.encap_secret(pubkey_bytes)
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(shared_secret).decode()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt", response_model=DecryptResponse)
def decrypt_key(data: DecryptRequest):
    try:
        ciphertext_bytes = base64.b64decode(data.ciphertext)
        shared_secret = kem.decap_secret(ciphertext_bytes)
        return {
            "shared_secret": base64.b64encode(shared_secret).decode()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
