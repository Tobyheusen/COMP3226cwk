# File: COMP3226CWK/run_mtls.py
import uvicorn
import ssl
import os
import sys

def main():
    # Configuration
    HOST = "127.0.0.1"
    PORT = 8000
    
    # SSL Paths
    SERVER_CERT = "server.crt"
    SERVER_KEY = "server.key"
    CA_CERT = "ca.crt"

    # Check if certs exist
    if not os.path.exists(SERVER_CERT) or not os.path.exists(CA_CERT):
        print("❌ Certificates not found in root directory!")
        print("   Please run 'python gen_mtls.py' first.")
        sys.exit(1)

    print("\n" + "="*60)
    print(f"🔐 STARTING SECURE mTLS SERVER")
    print(f"URL:     https://{HOST}:{PORT}")
    print("-" * 60)
    print("🔒 SECURITY: Client Certificate REQUIRED")
    print("   Browsers without 'client.p12' will be rejected.")
    print("   Scripts without 'client.crt'/'client.key' will fail.")
    print("="*60 + "\n")

    # Start Uvicorn with SSL Context
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        ssl_keyfile=SERVER_KEY,
        ssl_certfile=SERVER_CERT,
        ssl_ca_certs=CA_CERT,
        ssl_cert_reqs=ssl.CERT_REQUIRED,  # <--- CRITICAL: Enforces mTLS
        reload=True
    )

if __name__ == "__main__":
    main()