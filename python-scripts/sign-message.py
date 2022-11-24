from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def make_message_hash(msg):
    return SHA256.new(msg.encode('utf-8'))

def read_from_base64():
    return [ input(), decode_base64(input()) ]

# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
def sign(msg, key):
    # PKCS #1 v1.5 를 이용한 전자서명 생성 (RSA 전자서명)
    hash_obj = SHA256.new(msg)

    signer = pkcs1_15.new(key)  # 서명시 개인키(검증 시 public key)
    ans = signer.sign(hash_obj)  # 사인한 값, 메세지 해시 값 넣기.

    return ans

[msg, prikey] = read_from_base64()

sign_result = sign(msg, prikey)
print( encode_base64(sign_result) )