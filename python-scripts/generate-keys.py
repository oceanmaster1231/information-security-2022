from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import secrets

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

secret = secrets.token_bytes(32) # 32바이트 (256비트) 랜덤 비밀키 생성

prikey = RSA.generate(2048) # 개인키 export
pubkey = prikey.publickey().export_key() # 공개키 export

print(encode_base64(secret) + '\n')

print(encode_base64(pubkey) + '\n')
print(encode_base64(prikey) + '\n')
