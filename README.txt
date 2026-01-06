# COMP3226 - QR Login Prototype

This project is a **locally hosted QR-code login prototype** built with **Python** and **FastAPI**.
It demonstrates **Device Bound Session Credentials (DBSC)** using hardware-protected key pairs and **Mutual TLS (mTLS)** for channel security.

## Prerequisites

- **Python:** 3.10 or higher
- **Git:** For version control

## Installation

1.  Create and activate virtual environment:
    ```bash
    # macOS / Linux
    python3 -m venv venv
    source venv/bin/activate

    # Windows (PowerShell)
    python -m venv venv
    ./venv/Scripts/Activate.ps1
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Running with mTLS

This application enforces **Mutual TLS (mTLS)**. Both the server and the client (browser/mobile) must authenticate using certificates.

1.  Start the server:
    ```bash
    python run.py
    ```

    This script will:
    - Automatically generate a **Root CA**, **Server Cert**, and **Client Cert** if they don't exist.
    - Start the server on `0.0.0.0:8000` with mTLS enforced.
    - Output the generated certificates in the current directory.

2.  **Import Client Certificate:**
    - Locate the generated `client.p12` file.
    - **Password:** `secret`
    - **Desktop:** Import this file into your OS Keychain (macOS) or Browser Certificates (Windows/Chrome/Firefox).
    - **Mobile:** Transfer this file to your phone and install it in Settings -> Security -> Install from storage.

3.  **Access the Application:**
    - Visit the **LAN URL** printed in the console (e.g., `https://192.168.1.X:8000`).
    - Your browser will prompt you to select the "QR Login Client" certificate.
    - Proceed past the self-signed certificate warning (or import `ca.crt` as a trusted root).

## Troubleshooting

- **"Connection Reset" / "SSL Handshake Failed"**: This means your client did not present a valid certificate. Ensure `client.p12` is imported correctly.
- **"Web Crypto API not available"**: Ensure you are using `https://`.
