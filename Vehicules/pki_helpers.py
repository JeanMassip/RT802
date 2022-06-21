from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_private_key(filename: str, passphrase: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    utf8_pass = passphrase.encode("utf-8")
    algorithm = serialization.BestAvailableEncryption(utf8_pass)

    with open(filename, "wb") as keyfile:
        keyfile.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=algorithm,
            )
        )

    return private_key

def generate_csr(private_key, uuid, filename):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marne"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
            x509.NameAttribute(NameOID.COMMON_NAME, str(uuid)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Peugeot'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'PSA GROUP')
        ]
    )

    # Generate any alternative dns names

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
    )

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(filename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr