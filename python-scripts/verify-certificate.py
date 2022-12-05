from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64, json

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def make_cert_hash(name, pubKeyBase64):
	message = Hash(name + pubKeyBase64)
	return SHA256.new(message.encode('utf-8'))

def read_as_json():
	json_str = decode_base64(input()).decode('utf-8')
	json_obj = json.loads(json_str)
	return json_obj

# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
def verify(msg, key, signature):
    hash_obj = SHA256.new(msg)

    verifyer = pkcs1_15.new(key)  # base64 인코딩
    if verifyer.verify(hash_obj, signature):
        return True
    else:
        return False

cert = read_as_json()

hash_compare = SHA256.new(message) # 비교할 해시 생성
server_pubkey = RSA.import_key(open('public_key.der').read())  # bytes:서버 공개키 (HINT: JSON에는 BASE64 형태로 제공되어 있음)
signature = pkcs1_15.new(server_pubkey).sign(hash_compare) # bytes:서버 서명 (HINT: JSON에는 BASE64 형태로 제공되어 있음)

if cert['isValid']:
  print "The signature is valid." # 인증서 내 서명 검증

json_str = json.dumps(cert).encode('utf-8')

print(encode_base64(json_str))
