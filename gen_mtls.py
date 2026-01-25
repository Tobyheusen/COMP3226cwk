import os
import socket
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

# Configuration
CA_KEY = "ca.key"
CA_CERT = "ca.crt"
SERVER_KEY = "server.key"
SERVER_CERT = "server.crt"
CLIENT_KEY = "client.key"
CLIENT_CERT = "client.crt"
CLIENT_P12 = "client.p12"
P12_PASSWORD = b"secret" # Simple password for import

"""
script generates mTLS certificates for secure communication
"""

def get_lan_ip():
    try:
        # Try to find ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_certs():
    if os.path.exists(CLIENT_P12) and os.path.exists(SERVER_CERT):
        print("Using existing mTLS certificates.")
        return

    print("Generating mTLS Certificates...")

    # Generate CA so phone and server can trust each other
    print("- Generating Root CA...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"QR Login Root CA"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(ca_subject).issuer_name(issuer).public_key(
        ca_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    with open(CA_KEY, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CA_CERT, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Generate Server Cert
    print("- Generating Server Cert...")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    lan_ip = get_lan_ip()

    # Generate server identity
    sans = [
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress.IPv4Address(lan_ip))
    ]

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    server_cert = x509.CertificateBuilder().subject_name(server_subject).issuer_name(ca_subject).public_key(
        server_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(sans), critical=False,
    ).sign(ca_key, hashes.SHA256())

    with open(SERVER_KEY, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(SERVER_CERT, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print("- Generating Client Cert...")
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"QR Login Client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Authorized Device"),
    ])

    # Generate Client Cert for the users/ client device 
    client_cert = x509.CertificateBuilder().subject_name(client_subject).issuer_name(ca_subject).public_key(
        client_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=False
    ).sign(ca_key, hashes.SHA256())

    with open(CLIENT_KEY, "wb") as f:
        f.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CLIENT_CERT, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    # Package Client P12, takes the Client's Private Key and the Client's Public Certificate and puts them into a single file
    print("- Packaging client.p12...")
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"QR Login Client",
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(P12_PASSWORD)
    )
    with open(CLIENT_P12, "wb") as f:
        f.write(p12)

    print(f"Certs generated. Client P12 Password: 'secret'")

if __name__ == "__main__":
    generate_certs()
