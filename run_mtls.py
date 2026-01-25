import os
import sys
import ssl
import uvicorn
import gen_mtls

def main():
    # --- CONFIGURATION ---
    # Set this to False to allow phones to connect WITHOUT a client certificate
    # Set this to True to enforce strict mTLS security
    ENFORCE_MTLS = True  
    # ---------------------

    # 1. Ensure Certs Exist & Get IP
    gen_mtls.generate_certs()
    lan_ip = gen_mtls.get_lan_ip()
    port = 8000
    
    # 2. Setup Paths
    ca_cert = "ca.crt"
    server_cert = "server.crt"
    server_key = "server.key"

    # 3. Determine SSL Mode
    if ENFORCE_MTLS:
        ssl_mode = ssl.CERT_REQUIRED  # Strict: Reject anyone without a cert
        mode_name = "SECURE (mTLS)"
    else:
        ssl_mode = ssl.CERT_NONE      # Standard HTTPS: Anyone can connect
        mode_name = "STANDARD HTTPS (No Client Cert)"

    # 4. Print Status
    url = f"https://{lan_ip}:{port}"
    print("\n" + "="*60)
    print(f"SERVER STARTING: {mode_name}")
    print(f"URL:      {url}")
    print("-" * 60)
    
    if ENFORCE_MTLS:
        print("SECURITY: LOCKED. Client Certificate ('client.p12') REQUIRED.")
    else:
        print("SECURITY: OPEN. Devices can connect using standard HTTPS.")
        print("          (You will still see browser security warnings due to self-signed certs)")
    print("="*60 + "\n")

    # 5. Run Uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        ssl_keyfile=server_key,
        ssl_certfile=server_cert,
        ssl_ca_certs=ca_cert if ENFORCE_MTLS else None, # CA cert is only needed if verifying clients
        ssl_cert_reqs=ssl_mode,
        reload=True
    )

if __name__ == "__main__":
    main()