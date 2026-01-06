import os
import sys
import ssl
import uvicorn
import gen_mtls

def main():
    # 1. Ensure Certs Exist
    gen_mtls.generate_certs()

    lan_ip = gen_mtls.get_lan_ip()
    port = 8000

    ca_cert = "ca.crt"
    server_cert = "server.crt"
    server_key = "server.key"

    url = f"https://{lan_ip}:{port}"
    print("\n" + "="*60)
    print(f"🔒 mTLS SERVER STARTING")
    print(f"📡 LAN URL:  {url}")
    print(f"🏠 Local:    https://127.0.0.1:{port}")
    print("-" * 60)
    print("⚠️  REQUIREMENTS:")
    print("    1. Import 'client.p12' (Password: 'secret') into your Browser/Mobile.")
    print("    2. Import 'ca.crt' as a Trusted Root CA (Optional, removes warning).")
    print("="*60 + "\n")

    # Run Uvicorn with mTLS enforcement
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        ssl_keyfile=server_key,
        ssl_certfile=server_cert,
        ssl_ca_certs=ca_cert,
        ssl_cert_reqs=ssl.CERT_REQUIRED, # Enforce Client Cert
        reload=True
    )

if __name__ == "__main__":
    main()
