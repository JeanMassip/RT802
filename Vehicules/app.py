from pki_helpers import generate_private_key, generate_csr
from cryptography.hazmat.primitives.serialization import Encoding
from vehicule import Vehicule, VehiculeType
import requests, os, requests, uuid, time


vecid = uuid.uuid4()
# First Generate a private key
private_key = generate_private_key("vec-private-key.pem", "passphrase")
# Then generate the CSR
csr = generate_csr(private_key, vecid, "vec-csr.pem")
# Have the CSR signed
signreponse = requests.post("http://ca:5000/sign_csr", data=csr.public_bytes(Encoding.PEM))
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
authresponse = requests.post("http://broker:9000/auth", data=public_key)
authresponse.raise_for_status()
# Start sending messages
vec = Vehicule(str(vecid), VehiculeType.ORDINARY)
print("Sending msgs")
while(True):
    vec.default()
    time.sleep(5)

