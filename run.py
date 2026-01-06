import os
import socket
import ssl
import subprocess
import sys
import uvicorn

def get_lan_ip():
    try:
        # Connect to a public DNS server to determine the route
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_self_signed_cert(cert_file="cert.pem", key_file="key.pem"):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("✅ Using existing SSL certificates.")
        return

    print("🔑 Generating self-signed SSL certificates for HTTPS...")
    try:
        # Use openssl if available
        subprocess.check_call([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", key_file,
            "-out", cert_file, "-days", "365", "-nodes",
            "-subj", "/CN=localhost"
        ])
        print("✅ Certificates generated.")
    except FileNotFoundError:
        print("⚠️ OpenSSL not found. Trying to generate using Python 'trustme' or 'cryptography' if available, or failing.")
        # Fallback to pure python generation could be added here, but openssl is standard in most envs.
        # Let's try to use the 'cryptography' lib we installed.
        generate_cert_python(cert_file, key_file)
    except Exception as e:
        print(f"❌ Failed to generate certs: {e}")
        sys.exit(1)

def generate_cert_python(cert_file, key_file):
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256())

        with open(key_file, "wb") as f:
            f.write(key.private_key_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("✅ Certificates generated using Python cryptography.")

    except ImportError:
        print("❌ 'cryptography' library not found and 'openssl' missing. Install it with: pip install cryptography")
        sys.exit(1)

def main():
    lan_ip = get_lan_ip()
    port = 8000

    cert_file = "cert.pem"
    key_file = "key.pem"

    generate_self_signed_cert(cert_file, key_file)

    url = f"https://{lan_ip}:{port}"
    print("\n" + "="*60)
    print(f"🚀 SERVER STARTING")
    print(f"📡 LAN URL:  {url}")
    print(f"🏠 Local:    https://127.0.0.1:{port}")
    print("-" * 60)
    print("⚠️  NOTE: You will see a security warning in the browser")
    print("    because the certificate is self-signed.")
    print("    Proceed by clicking 'Advanced' -> 'Proceed to ... (unsafe)'.")
    print("="*60 + "\n")

    # Run Uvicorn
    # reload=True is useful for dev, but might not work well with programmtic launch if not careful.
    # We use uvicorn.run directly.

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        ssl_keyfile=key_file,
        ssl_certfile=cert_file,
        reload=True
    )

if __name__ == "__main__":
    main()
