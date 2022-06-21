from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import uuid

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

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_public_key(private_key, filename):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Champage-Ardennes"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AgbodjaMassip"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"CertificateAuthority"),
        ]
    )

    # Because this is self signed, the issuer is always the subject
    issuer = subject

    # This certificate is valid from now until 30 days
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=30)

    # Used to build the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    # Sign the certificate with the private key
    public_key = builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(filename, "wb") as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))

    return public_key

def generate_csr(private_key, filename):
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marne"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
            x509.NameAttribute(NameOID.COMMON_NAME, str(uuid.uuid4())),
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
    
# pki_helpers.py
def sign_csr(csr, ca_public_key, ca_private_key):
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=30)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_public_key.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
    )

    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    public_key = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return public_key.public_bytes(serialization.Encoding.PEM)

# ca_private_key = generate_private_key("ca-private-key.pem", "DtIflMN1M@nLJ_wSoHY~")
# ca_public_key = generate_public_key(ca_private_key, "ca-public-key.pem")