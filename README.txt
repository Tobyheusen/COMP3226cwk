# COMP3226 - QR Login Prototype

======== GROUP INFO ========
Group: 7

Title: Evaluating the Security of Quick Response Login Systems

======== Group Members ========
Toby Heusen
th2g23@soton.ac.uk

Aniscaan Shanthakumar
as2n23@soton.ac.uk

Alisa Udaltsova
au2g22@soton.ac.uk

Salim Babhair
sfsb1d22@soton.ac.uk

======== Prototype info and setup instructions ========

This is a locally hosted QR-code login prototype built with Pytho and FastAPI
It demonstrates Device Bound Session Credentials (DBSC) using hardware-protected key pairs and Mutual TLS (mTLS) for channel security

Installation:

1.  Create and activate virtual environment:
    # macOS / Linux
    python3 -m venv venv
    source venv/bin/activate

    # Windows (PowerShell)
    python -m venv venv
    ./venv/Scripts/Activate.ps1

2.  Install dependencies:
    pip install -r requirements.txt

Running:

1.  Start the server:
    # You might need to chmod this 

    # For non mtls, unsecure:
    python run.py 

    # For mtls, secure:
    python run_mtls.py 

    This script will:
    - Automatically generate a **Root CA**, **Server Cert**, and **Client Cert** if they don't exist.
    - Start the server on "X.X.X.X:8000" with mTLS enforced.
    - Output the generated certificates in the current directory.

2.  Import Client Certificate:
    - Find the generated "client.p12" file
    - The Password is: "secret"
    - To get this to work for browser on desktop: Open file in file explorer, should have a setup 
    - For mobile: Send this file to your phone (NOT VIA EMAIL, use onedrive/airdrop) and open it, should just work (you will see it in VPN config on iphone)

3.  Access the Application:
    - On desktop/laptop use the LAN URL printed in the console (e.g., "https://192.168.1.X:8000").
    - Your browser will prompt you to select the "QR Login Client" certificate.
    - Click the QR one the self-signed certificate warning (or import "ca.crt" as a trusted root, same process to do this as above)


