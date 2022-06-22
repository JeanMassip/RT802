import base64, json
from pki_helpers import generate_private_key, generate_csr
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from vehicule import Vehicule, VehiculeType
import requests, os, uuid, time, hashlib


vecid = uuid.uuid4()
# First Generate a private key
private_key = generate_private_key("vec-private-key.pem", "passphrase")
# Then generate the CSR
csr = generate_csr(private_key, vecid, "vec-csr.pem")
# Have the CSR signed
signreponse = requests.post("http://127.0.0.1:5000/sign_csr", data=csr.public_bytes(Encoding.PEM))
signreponse.raise_for_status()
public_key = signreponse.content
try:
    os.umask(0)
    with open(os.open("vec-public-key.pem", os.O_CREAT | os.O_WRONLY, 0o1600), 'w+') as crt_file_obj:
        crt_file_obj.write(str(public_key))
        crt_file_obj.close()
except:
    raise
# Authenticate to the broker
authresponse = requests.post("http://127.0.0.1:9000/auth", data=public_key)
authresponse.raise_for_status()
# Start sending messages
vec = Vehicule(str(vecid), VehiculeType.ORDINARY)
print("Sending msgs")
while(True):
    message = vec.default()
    prehash = hashlib.sha256(json.dumps(message["message"]).encode("utf-8")).hexdigest()
    sig = private_key.sign(prehash.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    message["signature"] = base64.b64encode(sig).decode("utf-8")
    vec.send_message(message, "/sensors/cam")
    time.sleep(5)

