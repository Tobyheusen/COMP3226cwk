# COMP3226 - QR Login Prototype

This is a locally hosted QR-code login prototype built with Pytho and FastAPI
It demonstrates Device Bound Session Credentials (DBSC) using hardware-protected key pairs and Mutual TLS (mTLS) for channel security

Prerequisites

Installation

1.  Create and activate virtual environment:
    # macOS / Linux
    python3 -m venv venv
    source venv/bin/activate

    # Windows (PowerShell)
    python -m venv venv
    ./venv/Scripts/Activate.ps1

2.  Install dependencies:
    pip install -r requirements.txt

## NEW STUFF: Running with mTLS

This will enforce **Mutual TLS (mTLS)** Both the server and the client (browser/mobile) so they must authenticate using certificates

1.  Start the server:
    # You might need to chmod this 
    python run.py 

    This script will:
    - Automatically generate a **Root CA**, **Server Cert**, and **Client Cert** if they don't exist.
    - Start the server on "0.0.0.0:8000" with mTLS enforced.
    - Output the generated certificates in the current directory.

2.  Import Client Certificate:
    - Find the generated "client.p12" file
    - The Password is : "secret"
    - To get this to work for browser on desktop: Open file in file explorer, should have a setup wizard 
    - For mobile: Send this file to your phone (NOT VIA EMAIL, use onedrive/airdrop or something ) and open it, should just work (you will see it in VPN config on iphone)

3.  Access the Application:
    - On desktop/laptop use the LAN URL printed in the console (e.g., "https://192.168.1.X:8000").
    - Your browser will prompt you to select the "QR Login Client" certificate.
    - Click the QR one the self-signed certificate warning (or import "ca.crt" as a trusted root, same process to do this as above)


!!!!!!!!!!!!!!!!!!! YOU NEED TO BE ON A PRIVATE NETWORK< WITH BOTH DEVICES ON THE SAME ONE NETWORK !!!!!!!!!!!!!!!!!!


